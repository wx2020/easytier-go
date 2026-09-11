// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package web

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math/rand"
	"net/http"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func generateCaptchaText(n int) string {
	letters := []rune("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func (s *Server) handleGetCaptcha(w http.ResponseWriter, r *http.Request) {
	sid := s.getOrCreateSessionID(w, r)
	text := generateCaptchaText(4)
	s.store.setCaptcha(sid, text)
	img := captchaImage(text)
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

func captchaImage(text string) image.Image {
	const W, H = 127, 48
	img := image.NewRGBA(image.Rect(0, 0, W, H))
	// background white
	for y := 0; y < H; y++ {
		for x := 0; x < W; x++ {
			img.Set(x, y, color.RGBA{255, 255, 255, 255})
		}
	}
	// noise lines
	for i := 0; i < 8; i++ {
		c := color.RGBA{uint8(rand.Intn(150)), uint8(rand.Intn(150)), uint8(rand.Intn(150)), 255}
		x1, y1 := rand.Intn(W), rand.Intn(H)
		x2, y2 := rand.Intn(W), rand.Intn(H)
		drawLine(img, x1, y1, x2, y2, c)
	}
	// draw text as simple 5x7 blocks
	colors := []color.RGBA{
		{200, 30, 30, 255},
		{30, 30, 200, 255},
		{30, 120, 30, 255},
		{120, 30, 120, 255},
	}
	for idx, ch := range text {
		col := colors[idx%len(colors)]
		baseX := 10 + idx*28 + rand.Intn(6) - 3
		baseY := 10 + rand.Intn(8) - 4
		drawChar(img, ch, baseX, baseY, col)
	}
	// noise dots
	for i := 0; i < 60; i++ {
		x, y := rand.Intn(W), rand.Intn(H)
		img.Set(x, y, color.RGBA{uint8(rand.Intn(255)), uint8(rand.Intn(255)), uint8(rand.Intn(255)), 255})
	}
	return img
}

func drawLine(img *image.RGBA, x1, y1, x2, y2 int, col color.RGBA) {
	dx := x2 - x1
	dy := y2 - y1
	steps := max(abs(dx), abs(dy))
	if steps == 0 {
		img.Set(x1, y1, col)
		return
	}
	for i := 0; i <= steps; i++ {
		x := x1 + dx*i/steps
		y := y1 + dy*i/steps
		img.Set(x, y, col)
	}
}

func drawChar(img *image.RGBA, ch rune, x0, y0 int, col color.RGBA) {
	// Very simple 5x7 bitmap for alphanumerics: use crude pattern
	// We draw each char as 3 vertical bars with varying heights to look like text
	// Not font-accurate but sufficient for captcha placeholder
	for dx := 0; dx < 12; dx++ {
		for dy := 0; dy < 18; dy++ {
			// create pseudo-random pattern based on char code
			v := (int(ch)*31 + dx*7 + dy*13) % 20
			if v < 9 {
				img.Set(x0+dx, y0+dy, col)
			}
		}
	}
}

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
