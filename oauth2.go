// Discordgo - Discord bindings for Go
// Available at https://github.com/bwmarrin/discordgo

// Copyright 2015-2016 Bruce Marriner <bruce@sqls.net>.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file contains functions related to Discord OAuth2 endpoints

package JuhGn9d5PBgMerWRbcSPYxSf

// ------------------------------------------------------------------------------------------------
// Code specific to Discord OAuth2 Applications
// ------------------------------------------------------------------------------------------------

// The MembershipState represents whether the user is in the team or has been invited into it
type MembershipState int

// Constants for the different stages of the MembershipState
const (
	MembershipStateInvited  MembershipState = 1
	MembershipStateAccepted MembershipState = 2
)

// A TeamMember struct stores values for a single Team Member, extending the normal User data - note that the user field is partial
type TeamMember struct {
	User            *User           `json:"user"`
	TeamID          string          `json:"team_id"`
	MembershipState MembershipState `json:"membership_state"`
	Permissions     []string        `json:"permissions"`
}

// A Team struct stores the members of a Discord Developer Team as well as some metadata about it
type Team struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Icon        string        `json:"icon"`
	OwnerID     string        `json:"owner_user_id"`
	Members     []*TeamMember `json:"members"`
}

// Application returns an Application structure of a specific Application
//   appID : The ID of an Application
func (s *Session) Application(appID string) (st *Application, err error) {
	return nil, nil
}

// Applications returns all applications for the authenticated user
func (s *Session) Applications() (st []*Application, err error) {
	return nil, nil
}

// ApplicationCreate creates a new Application
//    name : Name of Application / Bot
//    uris : Redirect URIs (Not required)
func (s *Session) ApplicationCreate(ap *Application) (st *Application, err error) {
	return nil, nil
}

// ApplicationUpdate updates an existing Application
//   var : desc
func (s *Session) ApplicationUpdate(appID string, ap *Application) (st *Application, err error) {
	return nil, nil
}

// ApplicationDelete deletes an existing Application
//   appID : The ID of an Application
func (s *Session) ApplicationDelete(appID string) (err error) {
	return nil
}

// Asset struct stores values for an asset of an application
type Asset struct {
	Type int    `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ApplicationAssets returns an application's assets
func (s *Session) ApplicationAssets(appID string) (ass []*Asset, err error) {
	return nil, nil
}

// ------------------------------------------------------------------------------------------------
// Code specific to Discord OAuth2 Application Bots
// ------------------------------------------------------------------------------------------------

// ApplicationBotCreate creates an Application Bot Account
//
//   appID : The ID of an Application
//
// NOTE: func name may change, if I can think up something better.
func (s *Session) ApplicationBotCreate(appID string) (st *User, err error) {
	return nil, nil
}
