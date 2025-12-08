// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: Copyright (c) 2024, Emir Aganovic

package diago

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/c2pc/diago/audio"
	"github.com/c2pc/diago/media"
	"github.com/c2pc/diago/media/sdp"
	"github.com/emiago/sipgo/sip"
)

var (
	HTTPDebug = os.Getenv("HTTP_DEBUG") == "true"
	// TODO remove client singleton
	client = http.Client{
		Timeout: 10 * time.Second,
	}

	errNoRTPSession = errors.New("no rtp session")
)

func init() {
	if HTTPDebug {
		client.Transport = &loggingTransport{}
	}
}

// DialogMedia is common struct for server and client session and it shares same functionality
// which is mostly arround media
type DialogMedia struct {
	mu sync.Mutex

	// media session is RTP local and remote
	// it is forked on media changes and updated on writer and reader
	// must be mutex protected
	// It MUST be always created on Media Session Init
	// Only safe to use after dialog Answered (Completed state)
	mediaSession *media.MediaSession

	// videoMediaSession is RTP session for video
	// Only created when video is supported
	videoMediaSession *media.MediaSession

	// rtp session is created for usage with RTPPacketReader and RTPPacketWriter
	// it adds RTCP layer and RTP monitoring before passing packets to MediaSession
	rtpSession *media.RTPSession
	// videoRtpSession is RTP session for video
	videoRtpSession *media.RTPSession

	// Packet reader is default reader for RTP audio stream
	// Use always AudioReader to get current Audio reader
	// Use this only as read only
	// It MUST be always created on Media Session Init
	// Only safe to use after dialog Answered (Completed state)
	RTPPacketReader *media.RTPPacketReader

	// Packet writer is default writer for RTP audio stream
	// Use always AudioWriter to get current Audio reader
	// Use this only as read only
	RTPPacketWriter *media.RTPPacketWriter

	// Video RTP packet reader and writer
	VideoRTPPacketReader *media.RTPPacketReader
	VideoRTPPacketWriter *media.RTPPacketWriter

	// In case we are chaining audio readers
	audioReader io.Reader
	audioWriter io.Writer

	// In case we are chaining video readers
	videoReader io.Reader
	videoWriter io.Writer

	// lastInvite is actual last invite sent by remote REINVITE
	// We do not use sipgo as this needs mutex but also keeping original invite
	lastInvite *sip.Request

	onClose       func() error
	onMediaUpdate func(*DialogMedia)

	closed bool
}

func (d *DialogMedia) Close() error {
	// Any hook attached
	// Prevent double exec
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true

	onClose := d.onClose
	d.onClose = nil
	m := d.mediaSession
	vm := d.videoMediaSession

	d.mu.Unlock()

	var e1, e2, e3 error
	if onClose != nil {
		e1 = onClose()
	}

	if m != nil {
		e2 = m.Close()
	}

	if vm != nil {
		e3 = vm.Close()
	}
	return errors.Join(e1, e2, e3)
}

func (d *DialogMedia) OnClose(f func() error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onCloseUnsafe(f)
}

func (d *DialogMedia) onCloseUnsafe(f func() error) {
	if d.onClose != nil {
		prev := d.onClose
		d.onClose = func() error {
			return errors.Join(prev(), f())
		}
		return
	}
	d.onClose = f
}

func (d *DialogMedia) InitMediaSession(m *media.MediaSession, r *media.RTPPacketReader, w *media.RTPPacketWriter) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.initMediaSessionUnsafe(m, r, w)
}

func (d *DialogMedia) initMediaSessionUnsafe(m *media.MediaSession, r *media.RTPPacketReader, w *media.RTPPacketWriter) {
	d.mediaSession = m
	d.RTPPacketReader = r
	d.RTPPacketWriter = w
}

func (d *DialogMedia) initRTPSessionUnsafe(m *media.MediaSession, rtpSess *media.RTPSession) {
	d.mediaSession = m
	d.rtpSession = rtpSess
	d.RTPPacketReader = media.NewRTPPacketReaderSession(rtpSess)
	d.RTPPacketWriter = media.NewRTPPacketWriterSession(rtpSess)
}

func (d *DialogMedia) initMediaSessionFromConf(conf MediaConfig) error {
	if d.mediaSession != nil || d.videoMediaSession != nil {
		// To allow testing or customizing current underhood session, this may be
		// precreated, so we want to return if already initialized.
		// Ex: To fake IO on RTP connection or different media stacks
		return nil
	}

	bindIP := conf.bindIP
	if bindIP == nil {
		var err error
		bindIP, _, err = sip.ResolveInterfacesIP("ip4", nil)
		if err != nil {
			return err
		}
	}

	// Separate audio and video codecs
	audioCodecs := []media.Codec{}
	videoCodecs := []media.Codec{}

	for _, codec := range conf.Codecs {
		if codec.Name == "H264" || codec.Name == "VP8" || codec.Name == "VP9" {
			videoCodecs = append(videoCodecs, codec)
		} else {
			audioCodecs = append(audioCodecs, codec)
		}
	}

	// Check that we have at least one codec
	if len(audioCodecs) == 0 && len(videoCodecs) == 0 {
		return fmt.Errorf("no codecs provided in MediaConfig")
	}

	// Create audio session
	if len(audioCodecs) > 0 {
		audioMode := conf.AudioMode
		if audioMode == "" {
			audioMode = sdp.ModeSendrecv
		}
		sess := &media.MediaSession{
			MediaType:  "audio",
			Codecs:     slices.Clone(audioCodecs),
			Laddr:      net.UDPAddr{IP: bindIP, Port: 0},
			ExternalIP: conf.externalIP,
			Mode:       audioMode,
			SecureRTP:  conf.secureRTP,
			SRTPAlg:    conf.SecureRTPAlg,
		}

		if err := sess.Init(); err != nil {
			return err
		}
		d.mediaSession = sess
	}

	// Create video session if video codecs are present
	if len(videoCodecs) > 0 {
		videoMode := conf.VideoMode
		if videoMode == "" {
			videoMode = sdp.ModeSendrecv
		}
		videoSess := &media.MediaSession{
			MediaType:  "video",
			Codecs:     slices.Clone(videoCodecs),
			Laddr:      net.UDPAddr{IP: bindIP, Port: 0},
			ExternalIP: conf.externalIP,
			Mode:       videoMode,
			SecureRTP:  conf.secureRTP,
			SRTPAlg:    conf.SecureRTPAlg,
		}

		if err := videoSess.Init(); err != nil {
			// If video session fails, we can still continue with audio only
			// but return error if audio also failed
			if d.mediaSession == nil {
				return fmt.Errorf("failed to initialize video session and no audio session: %w", err)
			}
		} else {
			d.videoMediaSession = videoSess
		}
	}

	return nil
}

// RTPSession returns underhood rtp session
// NOTE: this can be nil
func (d *DialogMedia) RTPSession() *media.RTPSession {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.rtpSession
}

func (d *DialogMedia) MediaSession() *media.MediaSession {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.mediaSession
}

func (d *DialogMedia) handleMediaUpdate(req *sip.Request, tx sip.ServerTransaction, contactHDR sip.Header) error {
	callID := ""
	if req != nil {
		callID = req.CallID().Value()
	}
	// TODO:
	fmt.Printf("[DIAGO_HANDLE_MEDIA_UPDATE] Начало handleMediaUpdate: CallID=%s\n", callID)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lastInvite = req

	if err := d.sdpReInviteUnsafe(req.Body()); err != nil {
		// TODO:
		fmt.Printf("[DIAGO_HANDLE_MEDIA_UPDATE] ОШИБКА sdpReInviteUnsafe: %v, CallID=%s\n", err, callID)
		return tx.Respond(sip.NewResponseFromRequest(req, sip.StatusRequestTerminated, "Request Terminated - "+err.Error(), nil))
	}

	// Reply with updated SDP
	// Combine audio and video SDP if both exist
	var sdpBody []byte
	if d.mediaSession != nil && d.videoMediaSession != nil {
		sessions := []*media.MediaSession{d.mediaSession, d.videoMediaSession}
		sdpBody = media.CombineSDP(sessions)
	} else if d.videoMediaSession != nil {
		sdpBody = d.videoMediaSession.LocalSDP()
	} else if d.mediaSession != nil {
		sdpBody = d.mediaSession.LocalSDP()
	} else {
		// TODO:
		fmt.Printf("[DIAGO_HANDLE_MEDIA_UPDATE] ОШИБКА: нет медиа сессий, CallID=%s\n", callID)
		return fmt.Errorf("no media session present")
	}
	res := sip.NewResponseFromRequest(req, sip.StatusOK, "OK", sdpBody)
	res.AppendHeader(contactHDR)
	res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	// TODO:
	fmt.Printf("[DIAGO_HANDLE_MEDIA_UPDATE] Отправка 200 OK в ответ на re-INVITE: CallID=%s, SDPLength=%d\n", callID, len(sdpBody))
	err := tx.Respond(res)
	if err != nil {
		// TODO:
		fmt.Printf("[DIAGO_HANDLE_MEDIA_UPDATE] ОШИБКА отправки 200 OK: %v, CallID=%s\n", err, callID)
	} else {
		// TODO:
		fmt.Printf("[DIAGO_HANDLE_MEDIA_UPDATE] УСПЕХ отправки 200 OK: CallID=%s\n", callID)
	}
	return err
}

// Must be protected with lock
func (d *DialogMedia) sdpReInviteUnsafe(sdp []byte) error {
	if d.mediaSession == nil && d.videoMediaSession == nil {
		return fmt.Errorf("no media session present")
	}

	if err := d.sdpUpdateUnsafe(sdp); err != nil {
		return err
	}

	if d.onMediaUpdate != nil {
		d.onMediaUpdate(d)
	}

	return nil
}

func (d *DialogMedia) checkEarlyMedia(remoteSDP []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	// RTP Session is only created when negotiation is finished. We use this to detect existing media
	if d.rtpSession == nil {
		return errNoRTPSession
	}
	return d.sdpUpdateUnsafe(remoteSDP)
}

func (d *DialogMedia) sdpUpdateUnsafe(sdpData []byte) error {
	if sdpData == nil {
		return nil
	}

	// Parse SDP to check for audio and video
	sd := sdp.SessionDescription{}
	if err := sdp.Unmarshal(sdpData, &sd); err != nil {
		return fmt.Errorf("failed to parse SDP: %w", err)
	}

	// Update audio session if it exists and audio is in SDP
	if d.mediaSession != nil {
		_, err := sd.MediaDescription("audio")
		if err == nil {
			// Audio is present in SDP
			msess := d.mediaSession.Fork()
			if err := msess.RemoteSDP(sdpData); err != nil {
				return fmt.Errorf("failed to update audio session: %w", err)
			}

			// Stop existing rtp
			if d.rtpSession != nil {
				if err := d.rtpSession.Close(); err != nil {
					return err
				}
			}

			rtpSess := media.NewRTPSession(msess)
			d.onCloseUnsafe(func() error {
				return rtpSess.Close()
			})

			if err := rtpSess.MonitorBackground(); err != nil {
				rtpSess.Close()
				return err
			}

			// Initialize or update audio RTP packet reader/writer
			if d.RTPPacketReader != nil {
				d.RTPPacketReader.UpdateRTPSession(rtpSess)
			} else {
				d.RTPPacketReader = media.NewRTPPacketReaderSession(rtpSess)
			}
			if d.RTPPacketWriter != nil {
				d.RTPPacketWriter.UpdateRTPSession(rtpSess)
			} else {
				d.RTPPacketWriter = media.NewRTPPacketWriterSession(rtpSess)
			}

			// update the reference
			d.mediaSession = msess
			d.rtpSession = rtpSess
		}
	}

	// Check if video is in SDP
	_, err := sd.MediaDescription("video")
	if err == nil {
		// Video is present in SDP
		if d.videoMediaSession == nil {
			// Video session doesn't exist, create it from remote SDP
			// Parse video codecs from remote SDP
			md, err := sd.MediaDescription("video")
			if err != nil {
				return fmt.Errorf("failed to get video media description: %w", err)
			}

			// Get attributes for video
			attrs := sd.MediaAttributes("video")
			if len(attrs) == 0 {
				attrs = sd.Values("a")
			}

			// Parse codecs from SDP
			codecs := make([]media.Codec, len(md.Formats))
			n, err := media.CodecsFromSDPRead(md.Formats, attrs, codecs)
			if err != nil || n == 0 {
				// If we can't parse codecs, use default video codecs
				codecs = []media.Codec{media.CodecVideoH264}
				n = 1
			}

			// Filter only video codecs
			videoCodecs := []media.Codec{}
			for i := 0; i < n; i++ {
				if codecs[i].Name == "H264" || codecs[i].Name == "VP8" || codecs[i].Name == "VP9" {
					videoCodecs = append(videoCodecs, codecs[i])
				}
			}

			// If no video codecs found, use default
			if len(videoCodecs) == 0 {
				videoCodecs = []media.Codec{media.CodecVideoH264}
			}

			// Get bind IP and settings from existing audio session
			bindIP := net.IP{}
			externalIP := net.IP{}
			secureRTP := 0
			srtpAlg := uint16(0)
			if d.mediaSession != nil {
				bindIP = d.mediaSession.Laddr.IP
				externalIP = d.mediaSession.ExternalIP
				secureRTP = d.mediaSession.SecureRTP
				srtpAlg = d.mediaSession.SRTPAlg
			} else {
				var err error
				bindIP, _, err = sip.ResolveInterfacesIP("ip4", nil)
				if err != nil {
					return fmt.Errorf("failed to resolve bind IP: %w", err)
				}
			}

			// Create video session
			videoSess := &media.MediaSession{
				MediaType:  "video",
				Codecs:     videoCodecs,
				Laddr:      net.UDPAddr{IP: bindIP, Port: 0},
				ExternalIP: externalIP,
				Mode:       sdp.ModeSendrecv,
				SecureRTP:  secureRTP,
				SRTPAlg:    srtpAlg,
			}

			if err := videoSess.Init(); err != nil {
				return fmt.Errorf("failed to initialize video session: %w", err)
			}

			d.videoMediaSession = videoSess
		}

		// Update video session
		vmsess := d.videoMediaSession.Fork()
		if err := vmsess.RemoteSDP(sdpData); err != nil {
			return fmt.Errorf("failed to update video session: %w", err)
		}

		// Stop existing video rtp
		if d.videoRtpSession != nil {
			if err := d.videoRtpSession.Close(); err != nil {
				return err
			}
		}

		videoRtpSess := media.NewRTPSession(vmsess)
		d.onCloseUnsafe(func() error {
			return videoRtpSess.Close()
		})

		if err := videoRtpSess.MonitorBackground(); err != nil {
			videoRtpSess.Close()
			return err
		}

		// Initialize or update video RTP packet reader/writer
		if d.VideoRTPPacketReader != nil {
			d.VideoRTPPacketReader.UpdateRTPSession(videoRtpSess)
		} else {
			d.VideoRTPPacketReader = media.NewRTPPacketReaderSession(videoRtpSess)
		}
		if d.VideoRTPPacketWriter != nil {
			d.VideoRTPPacketWriter.UpdateRTPSession(videoRtpSess)
		} else {
			d.VideoRTPPacketWriter = media.NewRTPPacketWriterSession(videoRtpSess)
		}

		// update the reference
		d.videoMediaSession = vmsess
		d.videoRtpSession = videoRtpSess
	} else {
		// Video is not in SDP - remove video session if exists
		if d.videoMediaSession != nil {
			// Close video RTP session if exists
			if d.videoRtpSession != nil {
				if err := d.videoRtpSession.Close(); err != nil {
					// Continue anyway
				}
				d.videoRtpSession = nil
			}

			// Close video media session to prevent sending video in response SDP
			if err := d.videoMediaSession.Close(); err != nil {
				// Continue anyway
			}
			d.videoMediaSession = nil
			d.VideoRTPPacketReader = nil
			d.VideoRTPPacketWriter = nil
			d.videoReader = nil
			d.videoWriter = nil
		}
	}

	return nil
}

type AudioReaderOption func(d *DialogMedia) error

type MediaProps struct {
	Codec media.Codec
	Laddr string
	Raddr string
}

func WithAudioReaderMediaProps(p *MediaProps) AudioReaderOption {
	return func(d *DialogMedia) error {
		p.Codec = media.CodecAudioFromSession(d.mediaSession)
		p.Laddr = d.mediaSession.Laddr.String()
		p.Raddr = d.mediaSession.Raddr.String()
		return nil
	}
}

// WithAudioReaderRTPStats creates RTP Statistics interceptor on audio reader
func WithAudioReaderRTPStats(hook media.OnRTPReadStats) AudioReaderOption {
	return func(d *DialogMedia) error {
		r := &media.RTPStatsReader{
			Reader:         d.getAudioReader(),
			RTPSession:     d.rtpSession,
			OnRTPReadStats: hook,
		}
		d.audioReader = r
		return nil
	}
}

// WithAudioReaderDTMF creates DTMF interceptor
func WithAudioReaderDTMF(r *DTMFReader) AudioReaderOption {
	return func(d *DialogMedia) error {
		r.dtmfReader = media.NewRTPDTMFReader(media.CodecTelephoneEvent8000, d.RTPPacketReader, d.getAudioReader())
		r.mediaSession = d.mediaSession

		d.audioReader = r
		return nil
	}
}

// AudioReader gets current audio reader. It MUST be called after Answer.
// Use AuidioListen for optimized reading.
// Reading buffer should be equal or bigger of media.RTPBufSize
// Options allow more intercepting audio reading like Stats or DTMF
// NOTE that this interceptors will stay,
func (d *DialogMedia) AudioReader(opts ...AudioReaderOption) (io.Reader, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, o := range opts {
		if err := o(d); err != nil {
			return nil, err
		}
	}
	return d.getAudioReader(), nil
}

func (d *DialogMedia) getAudioReader() io.Reader {
	if d.audioReader != nil {
		return d.audioReader
	}
	return d.RTPPacketReader
}

// audioReaderProps
func (d *DialogMedia) audioReaderProps(p *MediaProps) io.Reader {
	d.mu.Lock()
	defer d.mu.Unlock()

	WithAudioReaderMediaProps(p)(d)
	return d.getAudioReader()
}

// SetAudioReader adds/changes audio reader.
// Use this when you want to have interceptors of your audio
func (d *DialogMedia) SetAudioReader(r io.Reader) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.audioReader = r
}

type AudioWriterOption func(d *DialogMedia) error

func WithAudioWriterMediaProps(p *MediaProps) AudioWriterOption {
	return func(d *DialogMedia) error {
		p.Codec = media.CodecAudioFromSession(d.mediaSession)
		p.Laddr = d.mediaSession.Laddr.String()
		p.Raddr = d.mediaSession.Raddr.String()
		return nil
	}
}

// WithAudioReaderRTPStats creates RTP Statistics interceptor on audio reader
func WithAudioWriterRTPStats(hook media.OnRTPWriteStats) AudioWriterOption {
	return func(d *DialogMedia) error {
		w := media.RTPStatsWriter{
			Writer:          d.getAudioWriter(),
			RTPSession:      d.rtpSession,
			OnRTPWriteStats: hook,
		}
		d.audioWriter = &w
		return nil
	}
}

// WithAudioWriterDTMF creates DTMF interceptor
func WithAudioWriterDTMF(r *DTMFWriter) AudioWriterOption {
	return func(d *DialogMedia) error {
		r.dtmfWriter = media.NewRTPDTMFWriter(media.CodecTelephoneEvent8000, d.RTPPacketWriter, d.getAudioWriter())
		r.mediaSession = d.mediaSession
		d.audioWriter = r
		return nil
	}
}

func (d *DialogMedia) AudioWriter(opts ...AudioWriterOption) (io.Writer, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, o := range opts {
		if err := o(d); err != nil {
			return nil, err
		}
	}

	return d.getAudioWriter(), nil
}

func (d *DialogMedia) getAudioWriter() io.Writer {
	if d.audioWriter != nil {
		return d.audioWriter
	}
	return d.RTPPacketWriter
}

func (d *DialogMedia) audioWriterProps(p *MediaProps) io.Writer {
	d.mu.Lock()
	defer d.mu.Unlock()

	WithAudioWriterMediaProps(p)(d)
	return d.getAudioWriter()
}

// SetAudioWriter adds/changes audio reader.
// Use this when you want to have pipelines of your audio
func (d *DialogMedia) SetAudioWriter(r io.Writer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.audioWriter = r
}

// VideoReader gets current video reader. It MUST be called after Answer.
// Reading buffer should be equal or bigger of media.RTPBufSize
func (d *DialogMedia) VideoReader() (io.Reader, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.videoMediaSession == nil {
		return nil, fmt.Errorf("no video media session")
	}

	if d.VideoRTPPacketReader == nil {
		return nil, fmt.Errorf("no video RTP packet reader")
	}

	if d.videoReader != nil {
		return d.videoReader, nil
	}
	return d.VideoRTPPacketReader, nil
}

// VideoWriter gets current video writer. It MUST be called after Answer.
func (d *DialogMedia) VideoWriter() (io.Writer, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.videoMediaSession == nil {
		return nil, fmt.Errorf("no video media session")
	}

	if d.VideoRTPPacketWriter == nil {
		return nil, fmt.Errorf("no video RTP packet writer")
	}

	if d.videoWriter != nil {
		return d.videoWriter, nil
	}
	return d.VideoRTPPacketWriter, nil
}

// SetVideoReader adds/changes video reader.
// Use this when you want to have interceptors of your video
func (d *DialogMedia) SetVideoReader(r io.Reader) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.videoReader = r
}

// SetVideoWriter adds/changes video writer.
// Use this when you want to have pipelines of your video
func (d *DialogMedia) SetVideoWriter(r io.Writer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.videoWriter = r
}

// VideoMediaSession returns video media session
func (d *DialogMedia) VideoMediaSession() *media.MediaSession {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.videoMediaSession
}

// AddVideoSession dynamically adds video session during active call
// This allows adding video to an audio-only call using re-INVITE
// codecs: video codecs to use (e.g., media.CodecVideoH264)
// mode: SDP mode (sdp.ModeSendrecv, sdp.ModeRecvonly, sdp.ModeSendonly)
func (d *DialogMedia) AddVideoSession(codecs []media.Codec, mode string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.videoMediaSession != nil {
		return fmt.Errorf("video session already exists")
	}

	if len(codecs) == 0 {
		return fmt.Errorf("no video codecs provided")
	}

	// Get bind IP from existing audio session or resolve
	bindIP := net.IP{}
	if d.mediaSession != nil {
		bindIP = d.mediaSession.Laddr.IP
	} else {
		var err error
		bindIP, _, err = sip.ResolveInterfacesIP("ip4", nil)
		if err != nil {
			return fmt.Errorf("failed to resolve bind IP: %w", err)
		}
	}

	// Get external IP from existing audio session
	externalIP := net.IP{}
	if d.mediaSession != nil {
		externalIP = d.mediaSession.ExternalIP
	}

	// Get SRTP settings from existing audio session
	secureRTP := 0
	srtpAlg := uint16(0)
	if d.mediaSession != nil {
		secureRTP = d.mediaSession.SecureRTP
		srtpAlg = d.mediaSession.SRTPAlg
	}

	if mode == "" {
		mode = sdp.ModeSendrecv
	}

	videoSess := &media.MediaSession{
		MediaType:  "video",
		Codecs:     slices.Clone(codecs),
		Laddr:      net.UDPAddr{IP: bindIP, Port: 0},
		ExternalIP: externalIP,
		Mode:       mode,
		SecureRTP:  secureRTP,
		SRTPAlg:    srtpAlg,
	}

	if err := videoSess.Init(); err != nil {
		return fmt.Errorf("failed to initialize video session: %w", err)
	}

	d.videoMediaSession = videoSess
	return nil
}

// RemoveVideoSession removes video session during active call
// This allows removing video from a video call using re-INVITE
func (d *DialogMedia) RemoveVideoSession() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.videoMediaSession == nil {
		return nil // Already removed
	}

	// Close video RTP session if exists
	if d.videoRtpSession != nil {
		if err := d.videoRtpSession.Close(); err != nil {
			// Continue anyway
		}
		d.videoRtpSession = nil
	}

	// Close video media session
	if err := d.videoMediaSession.Close(); err != nil {
		// Continue anyway
	}

	d.videoMediaSession = nil
	d.VideoRTPPacketReader = nil
	d.VideoRTPPacketWriter = nil
	d.videoReader = nil
	d.videoWriter = nil

	return nil
}

func (d *DialogMedia) Media() *DialogMedia {
	return d
}

// Echo does audio echo for you
func (d *DialogMedia) Echo() error {
	audioR, err := d.AudioReader()
	if err != nil {
		return err
	}
	audioW, err := d.AudioWriter()
	if err != nil {
		return err
	}

	_, err = media.Copy(audioR, audioW)
	return err
}

// PlaybackCreate creates playback for audio
func (d *DialogMedia) PlaybackCreate() (AudioPlayback, error) {
	mprops := MediaProps{}
	w := d.audioWriterProps(&mprops)
	if w == nil {
		return AudioPlayback{}, fmt.Errorf("no media setup")
	}
	p := NewAudioPlayback(w, mprops.Codec)
	// On each play it needs reset RTP timestamp
	p.onPlay = d.RTPPacketWriter.ResetTimestamp
	return p, nil
}

// PlaybackControlCreate creates playback for audio with controls like mute unmute
func (d *DialogMedia) PlaybackControlCreate() (AudioPlaybackControl, error) {
	// NOTE we should avoid returning pointers for any IN dialplan to avoid heap
	mprops := MediaProps{}
	w := d.audioWriterProps(&mprops)

	if w == nil {
		return AudioPlaybackControl{}, fmt.Errorf("no media setup")
	}
	// Audio is controled via audio reader/writer
	control := &audioControl{
		Writer: w,
	}

	p := AudioPlaybackControl{
		AudioPlayback: NewAudioPlayback(control, mprops.Codec),
		control:       control,
	}
	return p, nil
}

// PlaybackRingtoneCreate is creating playback for ringtone
//
// Experimental
func (d *DialogMedia) PlaybackRingtoneCreate() (AudioRingtone, error) {
	mprops := MediaProps{}
	w := d.audioWriterProps(&mprops)
	if w == nil {
		return AudioRingtone{}, fmt.Errorf("no media setup")
	}

	ringtone, err := loadRingTonePCM(mprops.Codec)
	if err != nil {
		return AudioRingtone{}, err
	}

	encoder := audio.PCMEncoderWriter{}
	if err := encoder.Init(mprops.Codec, w); err != nil {
		return AudioRingtone{}, err
	}

	ar := AudioRingtone{
		writer:       &encoder,
		ringtone:     ringtone,
		sampleSize:   mprops.Codec.Samples16(),
		mediaSession: d.mediaSession,
	}
	return ar, nil
}

// AudioStereoRecordingCreate creates Stereo Recording audio Pipeline and stores as Wav file format
// For audio to be recorded use AudioReader and AudioWriter from Recording
//
// Tips:
// If you want to make permanent in audio pipeline use SetAudioReader, SetAudioWriter
//
// NOTE: API WILL change
func (d *DialogMedia) AudioStereoRecordingCreate(wawFile *os.File) (AudioStereoRecordingWav, error) {
	mpropsW := MediaProps{}
	aw := d.audioWriterProps(&mpropsW)
	if aw == nil {
		return AudioStereoRecordingWav{}, fmt.Errorf("no media setup")
	}

	mpropsR := MediaProps{}
	ar := d.audioReaderProps(&mpropsR)
	if ar == nil {
		return AudioStereoRecordingWav{}, fmt.Errorf("no media setup")
	}
	codec := mpropsW.Codec
	if mpropsR.Codec != mpropsW.Codec {
		return AudioStereoRecordingWav{}, fmt.Errorf("codecs of reader and writer need to match for stereo")
	}
	// Create wav file to store recording
	// Now create WavWriter to have Wav Container written
	wavWriter := audio.NewWavWriter(wawFile)

	mon := audio.MonitorPCMStereo{}
	if err := mon.Init(wavWriter, codec, ar, aw); err != nil {
		wavWriter.Close()
		return AudioStereoRecordingWav{}, err
	}

	r := AudioStereoRecordingWav{
		wawWriter: wavWriter,
		mon:       mon,
	}
	return r, nil
}

// Listen keeps reading stream until it gets closed or deadlined
// Use ListenBackground or ListenContext for better control
func (d *DialogMedia) Listen() (err error) {
	buf := make([]byte, media.RTPBufSize)
	audioReader, err := d.AudioReader()
	if err != nil {
		return err
	}

	for {
		_, err := audioReader.Read(buf)
		if err != nil {
			return err
		}
	}
}

// ListenBackground listens on stream in background and allows correct stoping of stream on network layer
func (d *DialogMedia) ListenBackground() (stop func() error, err error) {
	buf := make([]byte, media.RTPBufSize)
	audioReader, err := d.AudioReader()
	if err != nil {
		return nil, err
	}

	wg := sync.WaitGroup{}
	var readErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			_, err := audioReader.Read(buf)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return
				}
				readErr = err
				return
			}
		}
	}()

	return func() error {
		if err := d.mediaSession.StopRTP(1, 0); err != nil {
			return err
		}
		wg.Wait() // This makes sure we have exited reading
		return readErr
	}, nil
}

// ListenContext listens until context is canceled.
func (d *DialogMedia) ListenContext(pctx context.Context) error {
	buf := make([]byte, media.RTPBufSize)
	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		if pctx.Err() != nil {
			d.mediaSession.StopRTP(1, 0)
		}
	}()
	audioReader, err := d.AudioReader()
	if err != nil {
		return err
	}
	for {
		_, err := audioReader.Read(buf)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				return nil
			}
			return err
		}
	}
}

func (d *DialogMedia) ListenUntil(dur time.Duration) error {
	buf := make([]byte, media.RTPBufSize)

	d.mediaSession.StopRTP(1, dur)
	audioReader, err := d.AudioReader()
	if err != nil {
		return err
	}
	for {
		_, err := audioReader.Read(buf)
		if err != nil {
			return err
		}
	}
}

func (d *DialogMedia) StopRTP(rw int8, dur time.Duration) error {
	return d.mediaSession.StopRTP(rw, dur)
}

func (d *DialogMedia) StartRTP(rw int8, dur time.Duration) error {
	return d.mediaSession.StartRTP(rw)
}

type DTMFReader struct {
	mediaSession *media.MediaSession
	dtmfReader   *media.RTPDtmfReader
	onDTMF       func(dtmf rune) error
}

// AudioReaderDTMF is DTMF over RTP. It reads audio and provides hook for dtmf while listening for audio
// Use Listen or OnDTMF after this call
func (m *DialogMedia) AudioReaderDTMF() *DTMFReader {
	ar, _ := m.AudioReader()
	return &DTMFReader{
		dtmfReader:   media.NewRTPDTMFReader(media.CodecTelephoneEvent8000, m.RTPPacketReader, ar),
		mediaSession: m.mediaSession,
	}
}

func (d *DTMFReader) Listen(onDTMF func(dtmf rune) error, dur time.Duration) error {
	d.onDTMF = onDTMF
	buf := make([]byte, media.RTPBufSize)
	for {
		if _, err := d.readDeadline(buf, dur); err != nil {
			return err
		}
	}
}

// readDeadline(reads RTP until
func (d *DTMFReader) readDeadline(buf []byte, dur time.Duration) (n int, err error) {
	mediaSession := d.mediaSession
	if dur > 0 {
		// Stop RTP
		mediaSession.StopRTP(1, dur)
		defer mediaSession.StartRTP(2)
	}
	return d.Read(buf)
}

// OnDTMF must be called before audio reading
func (d *DTMFReader) OnDTMF(onDTMF func(dtmf rune) error) {
	d.onDTMF = onDTMF
}

// Read exposes io.Reader that can be used as AudioReader
func (d *DTMFReader) Read(buf []byte) (n int, err error) {
	// This is optimal way of reading audio and DTMF
	dtmfReader := d.dtmfReader
	n, err = dtmfReader.Read(buf)
	if err != nil {
		return n, err
	}

	if dtmf, ok := dtmfReader.ReadDTMF(); ok {
		if err := d.onDTMF(dtmf); err != nil {
			return n, err
		}
	}
	return n, nil
}

type DTMFWriter struct {
	mediaSession *media.MediaSession
	dtmfWriter   *media.RTPDtmfWriter
}

func (m *DialogMedia) AudioWriterDTMF() *DTMFWriter {
	return &DTMFWriter{
		dtmfWriter:   media.NewRTPDTMFWriter(media.CodecTelephoneEvent8000, m.RTPPacketWriter, m.getAudioWriter()),
		mediaSession: m.mediaSession,
	}
}

func (w *DTMFWriter) WriteDTMF(dtmf rune) error {
	return w.dtmfWriter.WriteDTMF(dtmf)
}

// AudioReader exposes DTMF audio writer. You should use this for parallel audio processing
func (w *DTMFWriter) AudioWriter() *media.RTPDtmfWriter {
	return w.dtmfWriter
}

// Write exposes as io.Writer that can be used as AudioWriter
func (w *DTMFWriter) Write(buf []byte) (n int, err error) {
	return w.dtmfWriter.Write(buf)
}
