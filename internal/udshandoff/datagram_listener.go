package udshandoff

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
)

// Type aliases to keep datagram_listener.go's reply-encoding code readable.
type (
	PP2Header = proxyproto.HeaderV2
	TLV       = proxyproto.TLV
)

// ListenDatagram binds a SOCK_DGRAM UDS socket at opts.SocketPath (or uses
// opts.PreboundPacketConn), receives datagrams, parses + validates each
// frame, and hands it off to handler.
//
// One goroutine handles the receive loop; per-datagram handlers run inline
// in the receive goroutine (Stage 1: no worker pool — sufficient for the
// flow rate, and per-datagram CPU is dominated by the handler's
// application-layer work which can be off-loaded if it becomes hot).
func ListenDatagram(ctx context.Context, opts ListenerOptions, handler DatagramHandler) (*DatagramListener, error) {
	if opts.Spec == nil {
		return nil, errors.New("udshandoff: ListenDatagram: opts.Spec is required")
	}
	if opts.Spec.L4 != "udp" {
		return nil, fmt.Errorf("udshandoff: protocol %q has L4=%s, not udp — use ListenStream", opts.Spec.Name, opts.Spec.L4)
	}
	if opts.Logger == nil {
		return nil, errors.New("udshandoff: ListenDatagram: opts.Logger is required")
	}
	if handler == nil {
		return nil, errors.New("udshandoff: ListenDatagram: handler is required")
	}
	var pc net.PacketConn
	if opts.PreboundPacketConn != nil {
		pc = opts.PreboundPacketConn
	} else {
		p, err := bindDatagram(opts.SocketPath)
		if err != nil {
			return nil, fmt.Errorf("udshandoff: bind dgram %s: %w", opts.SocketPath, err)
		}
		pc = p
	}
	dl := &DatagramListener{
		inner:   pc,
		opts:    opts,
		handler: handler,
		done:    make(chan struct{}),
	}
	dl.wg.Add(1)
	go dl.recvLoop(ctx)
	return dl, nil
}

// bindDatagram is the SOCK_DGRAM analogue of bindStream.
func bindDatagram(path string) (net.PacketConn, error) {
	if path == "" {
		return nil, errors.New("empty socket path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o2775); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	_ = os.Remove(path)
	pc, err := net.ListenPacket("unixgram", path)
	if err != nil {
		return nil, fmt.Errorf("listenpacket unixgram %s: %w", path, err)
	}
	if err := os.Chmod(path, SocketFileMode); err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("chmod %s: %w", path, err)
	}
	return pc, nil
}

// DatagramListener is the wrapper returned by ListenDatagram.
type DatagramListener struct {
	inner   net.PacketConn
	opts    ListenerOptions
	handler DatagramHandler

	mu      sync.Mutex
	closing bool
	wg      sync.WaitGroup
	done    chan struct{}
}

// LocalAddr returns the bound socket's address.
func (d *DatagramListener) LocalAddr() net.Addr { return d.inner.LocalAddr() }

// Close stops the receive loop, closes the socket, waits for in-flight
// handler goroutines, removes the socket file.
func (d *DatagramListener) Close() error {
	d.mu.Lock()
	if d.closing {
		d.mu.Unlock()
		return nil
	}
	d.closing = true
	d.mu.Unlock()
	err := d.inner.Close()
	close(d.done)
	d.wg.Wait()
	if d.opts.SocketPath != "" && d.opts.PreboundPacketConn == nil {
		_ = os.Remove(d.opts.SocketPath)
	}
	return err
}

// recvLoop is the receive goroutine.
func (d *DatagramListener) recvLoop(ctx context.Context) {
	defer d.wg.Done()
	logger := d.opts.Logger.With(
		slog.String("component", "udshandoff.dgram"),
		slog.String("protocol", string(d.opts.Spec.Name)),
		slog.String("socket", d.opts.SocketPath),
	)
	go func() {
		select {
		case <-ctx.Done():
			d.mu.Lock()
			closing := d.closing
			d.mu.Unlock()
			if !closing {
				_ = d.Close()
			}
		case <-d.done:
		}
	}()
	// MaxDatagramSize buffer per spec §2.6. One reusable buffer per goroutine
	// (we own the buffer single-threadedly here; if a handler needs to keep
	// the bytes it copies them).
	buf := make([]byte, MaxDatagramSize)
	for {
		n, peer, err := d.inner.ReadFrom(buf)
		if err != nil {
			d.mu.Lock()
			closing := d.closing
			d.mu.Unlock()
			if closing {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logger.Warn("recvfrom failed", slog.String("err", err.Error()))
			continue
		}
		if n > MaxDatagramSize {
			// Defence in depth: kernel hand-back exceeding cap. Bump
			// dropper counter, log, continue.
			d.opts.Metrics.IncOversizeDatagram()
			d.opts.Metrics.IncFrameRejected(d.opts.Spec.Name)
			logger.Warn("oversize datagram dropped",
				slog.Int("size", n),
				slog.Int("cap", MaxDatagramSize),
			)
			continue
		}
		// Slice for this iteration (so the parser sees only n bytes; the
		// underlying buffer is reused next iteration).
		frame := buf[:n]
		d.processFrame(ctx, frame, peer, logger)
	}
}

// processFrame parses, validates, and dispatches one datagram.
func (d *DatagramListener) processFrame(ctx context.Context, raw []byte, peer net.Addr, logger *slog.Logger) {
	parsed, err := DecodeDGramFrame(raw)
	if err != nil {
		d.onFrameError(err, logger)
		return
	}
	if parsed.Direction != DirFacadeToBackend {
		// Spec §5.5: backends MUST receive facade→backend frames only.
		// Backend→facade frames are emitted by THIS process via the Reply
		// function; receiving one means a misconfigured peer.
		d.opts.Metrics.IncFrameRejected(d.opts.Spec.Name)
		logger.Warn("datagram has fl bit-0 set (backend→facade direction)",
			slog.String("peer", peer.String()),
		)
		return
	}
	all := parsed.AllTLVs()
	res := d.opts.Spec.Validate(all)
	fields := LogFields{
		Protocol:    d.opts.Spec.Name,
		ClientSrc:   parsed.Inner.Src,
		OriginalDst: parsed.Inner.Dst,
	}
	fields.FromTLVs(all)
	if !res.OK {
		d.opts.Metrics.IncHandoffInvalid(d.opts.Spec.Name)
		extra := make([]slog.Attr, 0, 3)
		if len(res.MissingMandatory) > 0 {
			extra = append(extra, slog.Any("missing_mandatory", typesToHex(res.MissingMandatory)))
		}
		if len(res.PresentForbidden) > 0 {
			extra = append(extra, slog.Any("present_forbidden", typesToHex(res.PresentForbidden)))
		}
		if len(res.ValueErrors) > 0 {
			ve := make([]string, 0, len(res.ValueErrors))
			for _, e := range res.ValueErrors {
				ve = append(ve, fmt.Sprintf("0x%02x:%s", byte(e.Type), e.Err))
			}
			extra = append(extra, slog.Any("value_errors", ve))
		}
		fields.Event = EventHandoffInvalid
		fields.Extra = extra
		fields.EmitTo(logger, slog.LevelWarn, "datagram TLV validation failed")
		return
	}
	for _, t := range res.UnknownERA {
		d.opts.Metrics.IncUnknownERATLV(t, d.opts.Spec.Name)
		logger.Debug("unknown ERA TLV skipped (datagram)",
			slog.String("trace_id", fields.TraceID),
			slog.String("tlv_type", fmt.Sprintf("0x%02x", byte(t))),
		)
	}
	d.opts.Metrics.IncHandoffAccept(d.opts.Spec.Name)
	fields.BytesIn = int64(len(parsed.Payload))

	acc := &AcceptedDatagram{
		Frame:    parsed,
		Spec:     d.opts.Spec,
		Logger:   logger,
		Metrics:  d.opts.Metrics,
		Fields:   fields,
		PeerAddr: peer,
		Reply: func(payload []byte) error {
			return d.writeReply(parsed, peer, payload)
		},
	}
	if err := handlerDgramSafe(ctx, d.handler, acc); err != nil {
		fields.Event = EventFlowError
		fields.Extra = append(fields.Extra, slog.String("err", err.Error()))
		fields.EmitTo(logger, slog.LevelWarn, "datagram handler failed")
		return
	}
}

// writeReply re-frames a backend response datagram and sends it to the peer.
// The TLV block re-uses the inbound's inner PROXY-v2 envelope and ERA TLVs
// unchanged — per spec §5.5 the backend SHOULD swap src/dst in the inner
// envelope, but the facade does NOT trust the inner addresses on
// backend→facade frames; we keep them as-is so the response carries the
// trace_id + conn_id the facade routes by.
func (d *DatagramListener) writeReply(inbound *DGramFrame, peer net.Addr, payload []byte) error {
	// Re-encode the TLV block: the inner PROXY-v2 envelope as-is, then the
	// ERA TLVs concatenated in original order.
	innerBuf, err := encodeInnerPP2(inbound.Inner)
	if err != nil {
		return fmt.Errorf("encode inner pp2: %w", err)
	}
	eraBuf, err := encodeTLVs(inbound.ERA)
	if err != nil {
		return fmt.Errorf("encode era tlvs: %w", err)
	}
	tlvBlock := append(innerBuf, eraBuf...)
	if len(tlvBlock)+len(payload)+DGramHeaderLen > MaxDatagramSize {
		return fmt.Errorf("response oversize: %d > %d", len(tlvBlock)+len(payload)+DGramHeaderLen, MaxDatagramSize)
	}
	frame := make([]byte, DGramHeaderLen+len(tlvBlock)+len(payload))
	frame[0] = inbound.Version
	frame[1] = byte(DirBackendToFacade) & 0x01
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(tlvBlock)))
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(payload)))
	copy(frame[DGramHeaderLen:], tlvBlock)
	copy(frame[DGramHeaderLen+len(tlvBlock):], payload)
	_, err = d.inner.WriteTo(frame, peer)
	return err
}

// onFrameError is the datagram analogue of onHeaderError.
func (d *DatagramListener) onFrameError(err error, logger *slog.Logger) {
	d.opts.Metrics.IncFrameRejected(d.opts.Spec.Name)
	// Map the kind to the spec's counter set where possible.
	var fe *FrameErr
	if errors.As(err, &fe) {
		switch fe.Kind {
		case ErrFrameTooShort, ErrFrameTruncated:
			d.opts.Metrics.IncIncompleteHeader()
		case ErrFrameInnerPP2:
			// Inner-PP2 errors might be signature-invalid; preserve via
			// the wrapped error.
			d.opts.Metrics.IncProxyV2InvalidSignature()
		case ErrFrameOversize:
			d.opts.Metrics.IncOversizeDatagram()
		}
		logger.Warn("datagram frame parse failed",
			slog.String("kind", fe.Kind.String()),
			slog.String("detail", fe.Detail),
		)
		return
	}
	logger.Warn("datagram frame parse failed", slog.String("err", err.Error()))
}

func handlerDgramSafe(ctx context.Context, h DatagramHandler, acc *AcceptedDatagram) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("handler panic: %v", r)
		}
	}()
	return h(ctx, acc)
}

// encodeInnerPP2 re-encodes a parsed PROXY-v2 header back to its wire form.
// Used by the reply path; the parser handed us all the data we need.
func encodeInnerPP2(h *PP2Header) ([]byte, error) {
	return h.Encode()
}

// encodeTLVs serialises a slice of TLV records in source order (ascending
// type per spec §3.2 is the WRITER's responsibility; we preserve the order
// as parsed which is already what the facade sent).
func encodeTLVs(tlvs []TLV) ([]byte, error) {
	var buf bytes.Buffer
	for _, t := range tlvs {
		if len(t.Value) > 0xFFFF {
			return nil, fmt.Errorf("tlv 0x%02x value too long: %d", byte(t.Type), len(t.Value))
		}
		_ = buf.WriteByte(byte(t.Type))
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(t.Value)))
		_, _ = buf.Write(lenBuf[:])
		_, _ = buf.Write(t.Value)
	}
	return buf.Bytes(), nil
}
