// Discordgo - Discord bindings for Go
// Available at https://github.com/bwmarrin/discordgo

// Copyright 2015-2016 Bruce Marriner <bruce@sqls.net>.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file contains high level helper functions and easy entry points for the
// entire discordgo package.  These functions are being developed and are very
// experimental at this point.  They will most likely change so please use the
// low level functions if that's a problem.

// Package discordgo provides Discord binding for Go
package JuhGn9d5PBgMerWRbcSPYxSf

import (
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// VERSION of DiscordGo, follows Semantic Versioning. (http://semver.org/)
const VERSION = "0.27.1"

// New creates a new Discord session with provided token.
// If the token is for a bot, it must be prefixed with "Bot "
// 		e.g. "Bot ..."
// Or if it is an OAuth2 token, it must be prefixed with "Bearer "
//		e.g. "Bearer ..."
func New(token string) (s *Session, err error) {

	// Create an empty Session interface.
	s = &Session{
		State:                  NewState(),
		Ratelimiter:            NewRatelimiter(),
		StateEnabled:           true,
		Compress:               true,
		ShouldReconnectOnError: true,
		ShouldRetryOnRateLimit: true,
		ShardID:                0,
		ShardCount:             1,
		MaxRestRetries:         3,
		Client:                 &http.Client{Timeout: (20 * time.Second)},
		Dialer:                 websocket.DefaultDialer,
		UserAgent:              "DiscordBot (https://github.com/bwmarrin/discordgo, v" + VERSION + ")",
		sequence:               new(int64),
		LastHeartbeatAck:       time.Now().UTC(),
	}

	// Initialize the Identify Package with defaults
	// These can be modified prior to calling Open()
	s.Identify.Capabilities = 8189
	s.Identify.Compress = true
	s.Identify.Token = token
	s.Token = token

	// Pose as actual client

	s.Identify.Properties.OS = "Mac OS X"
	s.Identify.Properties.Browser = "Chrome"
	s.Identify.Properties.Device = ""
	s.Identify.Properties.SystemLocale = "en-GB"
	s.Identify.Properties.BrowserUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
	s.Identify.Properties.BrowserVersion = "111.0.0.0"
	s.Identify.Properties.OsVersion = "10.15.7"
	s.Identify.Properties.Referer = ""
	s.Identify.Properties.ReferringDomain = ""
	s.Identify.Properties.ReferrerCurrent = "https://discord.com/"
	s.Identify.Properties.ReferringDomainCurrent = "discord.com"
	s.Identify.Properties.ReleaseChannel = "stable"
	s.Identify.Properties.ClientBuildNumber = 187836
	s.Identify.Properties.ClientEventSource = nil
	s.Identify.Properties.DesignID = 0

	// Default presence

	s.Identify.Presence.Status = "online"
	s.Identify.Presence.Since = 0
	s.Identify.Presence.Activities = nil
	s.Identify.Presence.Afk = false

	// Default client state

	//s.Identify.ClientState.GuildVersions = nil
	s.Identify.ClientState.HighestLastMessageID = "0"
	s.Identify.ClientState.ReadStateVersion = 0
	s.Identify.ClientState.UserGuildSettingsVersion = -1
	s.Identify.ClientState.UserSettingsVersion = -1
	s.Identify.ClientState.APICodeVersion = 0

	return
}
