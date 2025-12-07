// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: Copyright (c) 2024, Emir Aganovic

package diago

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/c2pc/diago/media"
	"github.com/c2pc/diago/media/sdp"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// DialogServerSession represents inbound channel
type DialogServerSession struct {
	*sipgo.DialogServerSession

	// MediaSession *media.MediaSession
	DialogMedia

	onReferDialog func(referDialog *DialogClientSession)

	mediaConf MediaConfig
	closed    atomic.Uint32
}

func (d *DialogServerSession) Id() string {
	return d.ID
}

func (d *DialogServerSession) Close() error {
	if !d.closed.CompareAndSwap(0, 1) {
		return nil
	}
	e1 := d.DialogMedia.Close()
	e2 := d.DialogServerSession.Close()
	return errors.Join(e1, e2)
}

func (d *DialogServerSession) FromUser() string {
	return d.InviteRequest.From().Address.User
}

// User that was dialed
func (d *DialogServerSession) ToUser() string {
	return d.InviteRequest.To().Address.User
}

func (d *DialogServerSession) Transport() string {
	return d.InviteRequest.Transport()
}

func (d *DialogServerSession) Trying() error {
	return d.Respond(sip.StatusTrying, "Trying", nil)
}

// Progress sends 100 trying.
//
// Deprecated: Use Trying. It will change behavior to 183 Sesion Progress in future releases
func (d *DialogServerSession) Progress() error {
	return d.Respond(sip.StatusTrying, "Trying", nil)
}

// ProgressMedia sends 183 Session Progress and creates early media
//
// Experimental: Naming of API might change
func (d *DialogServerSession) ProgressMedia() error {
	if err := d.initMediaSessionFromConf(d.mediaConf); err != nil {
		return err
	}
	rtpSess := media.NewRTPSession(d.mediaSession)
	if err := d.setupRTPSession(rtpSess); err != nil {
		return err
	}

	headers := []sip.Header{sip.NewHeader("Content-Type", "application/sdp")}
	// Combine audio and video SDP if both exist
	var body []byte
	if rtpSess.Sess != nil && d.videoMediaSession != nil {
		sessions := []*media.MediaSession{rtpSess.Sess, d.videoMediaSession}
		body = media.CombineSDP(sessions)
	} else if d.videoMediaSession != nil {
		body = d.videoMediaSession.LocalSDP()
	} else if rtpSess.Sess != nil {
		body = rtpSess.Sess.LocalSDP()
	} else {
		return fmt.Errorf("no media session available")
	}
	if err := d.DialogServerSession.Respond(183, "Session Progress", body, headers...); err != nil {
		return err
	}
	return rtpSess.MonitorBackground()
}

func (d *DialogServerSession) Ringing() error {
	return d.Respond(sip.StatusRinging, "Ringing", nil)
}

func (d *DialogServerSession) DialogSIP() *sipgo.Dialog {
	return &d.Dialog
}

func (d *DialogServerSession) RemoteContact() *sip.ContactHeader {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.lastInvite != nil {
		return d.lastInvite.Contact()
	}
	return d.InviteRequest.Contact()
}

func (d *DialogServerSession) RespondSDP(body []byte) error {
	headers := []sip.Header{sip.NewHeader("Content-Type", "application/sdp")}
	return d.DialogServerSession.Respond(200, "OK", body, headers...)
}

// Answer creates media session and answers
// After this new AudioReader and AudioWriter are created for audio manipulation
// NOTE: Not final API
func (d *DialogServerSession) Answer() error {
	// Media Exists as early
	if d.mediaSession != nil || d.videoMediaSession != nil {
		// This will now block until ACK received with 64*T1 as max.
		var sdpBody []byte
		if d.mediaSession != nil && d.videoMediaSession != nil {
			sessions := []*media.MediaSession{d.mediaSession, d.videoMediaSession}
			sdpBody = media.CombineSDP(sessions)
		} else if d.videoMediaSession != nil {
			sdpBody = d.videoMediaSession.LocalSDP()
		} else {
			sdpBody = d.mediaSession.LocalSDP()
		}
		if err := d.RespondSDP(sdpBody); err != nil {
			return err
		}
		return nil
	}

	if err := d.initMediaSessionFromConf(d.mediaConf); err != nil {
		return err
	}

	rtpSess := media.NewRTPSession(d.mediaSession)
	return d.answerSession(rtpSess)
}

type AnswerOptions struct {
	// OnMediaUpdate triggers when media update happens. It is blocking func, so make sure you exit
	OnMediaUpdate func(d *DialogMedia)
	OnRefer       func(referDialog *DialogClientSession)
	// Codecs that will be used
	Codecs []media.Codec
}

// AnswerOptions allows to answer dialog with options
// Experimental
//
// NOTE: API may change
func (d *DialogServerSession) AnswerOptions(opt AnswerOptions) error {
	d.mu.Lock()
	d.onReferDialog = opt.OnRefer
	d.onMediaUpdate = opt.OnMediaUpdate
	d.mu.Unlock()

	// If media exists as early, only respond 200
	if d.mediaSession != nil || d.videoMediaSession != nil {
		// Check do codecs match
		var sdpBody []byte
		if d.mediaSession != nil && d.videoMediaSession != nil {
			sessions := []*media.MediaSession{d.mediaSession, d.videoMediaSession}
			sdpBody = media.CombineSDP(sessions)
		} else if d.videoMediaSession != nil {
			sdpBody = d.videoMediaSession.LocalSDP()
		} else {
			sdpBody = d.mediaSession.LocalSDP()
		}
		if err := d.RespondSDP(sdpBody); err != nil {
			return err
		}
		return nil
	}

	// Let override of formats
	conf := d.mediaConf
	if opt.Codecs != nil {
		conf.Codecs = opt.Codecs
	}

	if err := d.initMediaSessionFromConf(conf); err != nil {
		return err
	}

	// Check if we have at least one media session
	if d.mediaSession == nil && d.videoMediaSession == nil {
		return fmt.Errorf("no media session available")
	}

	// Use audio session if available, otherwise video
	var rtpSess *media.RTPSession
	if d.mediaSession != nil {
		rtpSess = media.NewRTPSession(d.mediaSession)
	} else if d.videoMediaSession != nil {
		rtpSess = media.NewRTPSession(d.videoMediaSession)
	}

	return d.answerSession(rtpSess)
}

// answerSession. It allows answering with custom RTP Session.
// NOTE: Not final API
func (d *DialogServerSession) answerSession(rtpSess *media.RTPSession) error {
	// TODO: Use setupRTPSession
	sess := rtpSess.Sess
	sdpBody := d.InviteRequest.Body()
	if sdpBody == nil {
		return fmt.Errorf("no sdp present in INVITE")
	}

	// Parse SDP to check for audio and video
	sd := sdp.SessionDescription{}
	if err := sdp.Unmarshal(sdpBody, &sd); err != nil {
		return fmt.Errorf("failed to parse SDP: %w", err)
	}

	// Update session based on its media type
	// Check if session matches the media type in SDP
	mediaType := sess.MediaType
	if mediaType == "" {
		mediaType = "audio" // Default
	}

	// Ensure session is initialized (port is set)
	if sess.Laddr.Port == 0 {
		// Session not initialized, try to initialize it
		if err := sess.Init(); err != nil {
			return fmt.Errorf("failed to initialize %s session: %w", mediaType, err)
		}
	}

	_, err := sd.MediaDescription(mediaType)
	if err == nil {
		// Media type is present in SDP
		if err := sess.RemoteSDP(sdpBody); err != nil {
			// If no supported codecs found, we should still try to answer
			// with what we have, but log the error
			// Check if we have any codecs at all
			commonCodecs := sess.CommonCodecs()
			if len(sess.Codecs) == 0 && len(commonCodecs) == 0 {
				return fmt.Errorf("failed to apply %s SDP: %w", mediaType, err)
			}
			// If we have some codecs, continue (they might be from previous negotiation)
		}
	}

	d.mu.Lock()
	d.initRTPSessionUnsafe(sess, rtpSess)
	// Close RTP session
	d.onCloseUnsafe(func() error {
		return rtpSess.Close()
	})
	d.mu.Unlock()

	// Update video session if it exists and video is in SDP
	// Also create video session if video is in SDP but not in our config
	_, err = sd.MediaDescription("video")
	if err == nil {
		// Video is present in SDP
		if d.videoMediaSession == nil {
			// Video session doesn't exist, but video is in SDP
			// Create it dynamically - parse video codecs from remote SDP
			md, mdErr := sd.MediaDescription("video")
			if mdErr == nil {
				// Get attributes for video
				attrs := sd.MediaAttributes("video")
				if len(attrs) == 0 {
					attrs = sd.Values("a")
				}

				// Parse codecs from SDP
				// Создаем массив с запасом, так как CodecsFromSDPRead может попытаться записать больше элементов
				// если есть динамические кодеки
				maxCodecs := len(md.Formats) + 4 // Запас для динамических кодеков
				codecs := make([]media.Codec, maxCodecs)
				n, codecErr := media.CodecsFromSDPRead(md.Formats, attrs, codecs)
				if codecErr != nil || n == 0 {
					// If we can't parse codecs, use default video codecs
					codecs = []media.Codec{media.CodecVideoH264}
					n = 1
				} else if n > maxCodecs {
					// На всякий случай ограничиваем n размером массива
					n = maxCodecs
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
				if sess != nil {
					bindIP = sess.Laddr.IP
					externalIP = sess.ExternalIP
					secureRTP = sess.SecureRTP
					srtpAlg = sess.SRTPAlg
				} else {
					var resolveErr error
					bindIP, _, resolveErr = sip.ResolveInterfacesIP("ip4", nil)
					if resolveErr != nil {
						// Continue without video if can't resolve IP
						bindIP = nil
					}
				}

				// Create video session if we have bind IP
				if bindIP != nil {
					videoSess := &media.MediaSession{
						MediaType:  "video",
						Codecs:     videoCodecs,
						Laddr:      net.UDPAddr{IP: bindIP, Port: 0},
						ExternalIP: externalIP,
						Mode:       sdp.ModeSendrecv,
						SecureRTP:  secureRTP,
						SRTPAlg:    srtpAlg,
					}

					if initErr := videoSess.Init(); initErr == nil {
						d.mu.Lock()
						d.videoMediaSession = videoSess
						d.mu.Unlock()
					}
				}
			}
		}

		if d.videoMediaSession != nil {
			// Ensure video session is initialized (port is set)
			if d.videoMediaSession.Laddr.Port == 0 {
				// Session not initialized, try to initialize it
				if err := d.videoMediaSession.Init(); err != nil {
					// If video session fails to initialize, continue with audio only
					// but log the error
				}
			}

			// Video session exists, update it
			remoteSDPErr := d.videoMediaSession.RemoteSDP(sdpBody)

			// Even if RemoteSDP returns error, we need to ensure Raddr is set
			// if video is in SDP, otherwise ReadRTP will block
			if remoteSDPErr != nil {
				// Try to set Raddr manually from SDP
				md, mdErr := sd.MediaDescription("video")
				if mdErr == nil {
					ci, ciErr := sd.ConnectionInformation()
					if ciErr == nil {
						// Set remote address even if codec negotiation failed
						d.videoMediaSession.SetRemoteAddr(&net.UDPAddr{IP: ci.IP, Port: md.Port})
					}
				}

				// Check if we have any video codecs at all
				commonCodecs := d.videoMediaSession.CommonCodecs()
				if len(d.videoMediaSession.Codecs) == 0 && len(commonCodecs) == 0 {
					// No video codecs, continue with audio only
				} else {
					// We have some codecs, but negotiation failed - continue anyway
				}
			}

			// Verify that Raddr is set before creating RTP session
			if d.videoMediaSession.Raddr.IP == nil {
				// Raddr not set, try to set it from SDP
				md, mdErr := sd.MediaDescription("video")
				if mdErr == nil {
					ci, ciErr := sd.ConnectionInformation()
					if ciErr == nil {
						d.videoMediaSession.SetRemoteAddr(&net.UDPAddr{IP: ci.IP, Port: md.Port})
					}
				}
			}

			videoRtpSess := media.NewRTPSession(d.videoMediaSession)
			d.mu.Lock()
			d.videoRtpSession = videoRtpSess
			d.VideoRTPPacketReader = media.NewRTPPacketReaderSession(videoRtpSess)
			d.VideoRTPPacketWriter = media.NewRTPPacketWriterSession(videoRtpSess)
			d.onCloseUnsafe(func() error {
				return videoRtpSess.Close()
			})
			d.mu.Unlock()

			// Must be called after reader and writer setup due to race
			if err := videoRtpSess.MonitorBackground(); err != nil {
				return err
			}
		}
	}

	// This will now block until ACK received with 64*T1 as max.
	// How to let caller to cancel this?
	// Combine audio and video SDP if both exist
	var localSDP []byte
	if sess != nil && d.videoMediaSession != nil {
		sessions := []*media.MediaSession{sess, d.videoMediaSession}
		localSDP = media.CombineSDP(sessions)
	} else if d.videoMediaSession != nil {
		localSDP = d.videoMediaSession.LocalSDP()
	} else if sess != nil {
		localSDP = sess.LocalSDP()
	} else {
		return fmt.Errorf("no media session available")
	}
	if err := d.RespondSDP(localSDP); err != nil {
		return err
	}
	// Must be called after media and reader writer is setup
	return rtpSess.MonitorBackground()
}

func (d *DialogServerSession) setupRTPSession(rtpSess *media.RTPSession) error {
	sess := rtpSess.Sess
	sdpBody := d.InviteRequest.Body()
	if sdpBody == nil {
		return fmt.Errorf("no sdp present in INVITE")
	}

	// Parse SDP to check for audio
	sd := sdp.SessionDescription{}
	if err := sdp.Unmarshal(sdpBody, &sd); err != nil {
		return fmt.Errorf("failed to parse SDP: %w", err)
	}

	// Update audio session if audio is in SDP
	_, err := sd.MediaDescription("audio")
	if err == nil {
		// Audio is present in SDP
		if err := sess.RemoteSDP(sdpBody); err != nil {
			return err
		}
	}

	d.mu.Lock()
	d.initRTPSessionUnsafe(sess, rtpSess)
	// Close RTP session
	d.onCloseUnsafe(func() error {
		return rtpSess.Close()
	})
	d.mu.Unlock()
	return nil
}

// AnswerLate does answer with Late offer.
func (d *DialogServerSession) AnswerLate() error {
	if err := d.initMediaSessionFromConf(d.mediaConf); err != nil {
		return err
	}
	sess := d.mediaSession
	rtpSess := media.NewRTPSession(sess)
	localSDP := sess.LocalSDP()

	d.mu.Lock()
	d.initRTPSessionUnsafe(sess, rtpSess)
	// Close RTP session
	d.onCloseUnsafe(func() error {
		return rtpSess.Close()
	})
	d.mu.Unlock()

	// This will now block until ACK received with 64*T1 as max.
	// How to let caller to cancel this?
	var sdpBody []byte
	if d.videoMediaSession != nil {
		sessions := []*media.MediaSession{sess, d.videoMediaSession}
		sdpBody = media.CombineSDP(sessions)
	} else {
		sdpBody = localSDP
	}
	if err := d.RespondSDP(sdpBody); err != nil {
		return err
	}
	// Must be called after media and reader writer is setup
	return rtpSess.MonitorBackground()
}

func (d *DialogServerSession) ReadAck(req *sip.Request, tx sip.ServerTransaction) error {
	// Check do we have some session
	err := func() error {
		d.mu.Lock()
		defer d.mu.Unlock()
		sess := d.mediaSession
		if sess == nil {
			return nil
		}
		contentType := req.ContentType()
		if contentType == nil {
			return nil
		}
		body := req.Body()
		if body != nil && contentType.Value() == "application/sdp" {
			// This is Late offer response
			// Parse SDP to check for audio
			sd := sdp.SessionDescription{}
			if err := sdp.Unmarshal(body, &sd); err == nil {
				// Check if audio is in SDP
				_, err := sd.MediaDescription("audio")
				if err == nil {
					// Audio is present in SDP
					if err := sess.RemoteSDP(body); err != nil {
						return err
					}
				}
			} else {
				// Fallback: try to apply SDP anyway (for backward compatibility)
				if err := sess.RemoteSDP(body); err != nil {
					return err
				}
			}
		}
		return nil
	}()
	if err != nil {
		e := d.Hangup(d.Context())
		return errors.Join(err, e)
	}

	return d.DialogServerSession.ReadAck(req, tx)
}

func (d *DialogServerSession) Hangup(ctx context.Context) error {
	state := d.LoadState()
	if state == sip.DialogStateConfirmed {
		return d.Bye(ctx)
	}
	return d.Respond(sip.StatusTemporarilyUnavailable, "Temporarly unavailable", nil)
}

func (d *DialogServerSession) ReInvite(ctx context.Context) error {
	var sdpBody []byte
	if d.mediaSession != nil && d.videoMediaSession != nil {
		sessions := []*media.MediaSession{d.mediaSession, d.videoMediaSession}
		sdpBody = media.CombineSDP(sessions)
	} else if d.videoMediaSession != nil {
		sdpBody = d.videoMediaSession.LocalSDP()
	} else if d.mediaSession != nil {
		sdpBody = d.mediaSession.LocalSDP()
	} else {
		return fmt.Errorf("no media session available")
	}
	contact := d.RemoteContact()
	req := sip.NewRequest(sip.INVITE, contact.Address)
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	req.SetBody(sdpBody)

	res, err := d.Do(ctx, req)
	if err != nil {
		return err
	}

	if !res.IsSuccess() {
		return sipgo.ErrDialogResponse{
			Res: res,
		}
	}

	cont := res.Contact()
	if cont == nil {
		return fmt.Errorf("reinvite: no contact header present")
	}

	ack := sip.NewRequest(sip.ACK, cont.Address)
	return d.WriteRequest(ack)
}

// Refer tries todo refer (blind transfer) on call
func (d *DialogServerSession) Refer(ctx context.Context, referTo sip.Uri, headers ...sip.Header) error {
	cont := d.InviteRequest.Contact()
	return dialogRefer(ctx, d, cont.Address, referTo, headers...)
}

func (d *DialogServerSession) handleReferNotify(req *sip.Request, tx sip.ServerTransaction) {
	dialogHandleReferNotify(d, req, tx)
}

func (d *DialogServerSession) handleRefer(dg *Diago, req *sip.Request, tx sip.ServerTransaction) {
	d.mu.Lock()
	onRefDialog := d.onReferDialog
	d.mu.Unlock()
	if onRefDialog == nil {
		tx.Respond(sip.NewResponseFromRequest(req, sip.StatusNotAcceptable, "Not Acceptable", nil))
		return
	}

	dialogHandleRefer(d, dg, req, tx, onRefDialog)
}

func (d *DialogServerSession) handleReInvite(req *sip.Request, tx sip.ServerTransaction) error {
	if err := d.ReadRequest(req, tx); err != nil {
		return tx.Respond(sip.NewResponseFromRequest(req, sip.StatusBadRequest, err.Error(), nil))
	}

	return d.handleMediaUpdate(req, tx, d.InviteResponse.Contact())
}

func (d *DialogServerSession) readSIPInfoDTMF(req *sip.Request, tx sip.ServerTransaction) error {
	return tx.Respond(sip.NewResponseFromRequest(req, sip.StatusNotAcceptable, "Not Acceptable", nil))
	// if err := d.ReadRequest(req, tx); err != nil {
	// 	tx.Respond(sip.NewResponseFromRequest(req, sip.StatusBadRequest, "Bad Request", nil))
	// 	return
	// }

	// Parse this
	//Signal=1
	// Duration=160
	// reader := bytes.NewReader(req.Body())

	// for {

	// }
}
