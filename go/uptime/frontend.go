// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package uptime

import (
	"net/http"
	"os"
	"path/filepath"
)

func (s *Server) frontendHandler() http.Handler {
	candidates := []string{
		"easytier-contrib/easytier-uptime/frontend/dist",
		"../easytier-contrib/easytier-uptime/frontend/dist",
		"../../easytier-contrib/easytier-uptime/frontend/dist",
		"./dist",
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(p)
			return http.FileServer(http.Dir(abs))
		}
	}
	if pwd, err := os.Getwd(); err == nil {
		for _, rel := range []string{"easytier-contrib/easytier-uptime/frontend/dist", "frontend/dist"} {
			joined := filepath.Join(pwd, rel)
			if info, err := os.Stat(joined); err == nil && info.IsDir() {
				return http.FileServer(http.Dir(joined))
			}
		}
	}
	return nil
}
