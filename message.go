// Discordgo - Discord bindings for Go
// Available at https://github.com/bwmarrin/discordgo

// Copyright 2015-2016 Bruce Marriner <bruce@sqls.net>.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file contains code related to the Message struct

package JuhGn9d5PBgMerWRbcSPYxSf

import (
	"github.com/json-iterator/go"
	_ "encoding/json"
	"io"
	"regexp"
	"strings"
)

// MessageType is the type of Message
// https://discord.com/developers/docs/resources/channel#message-object-message-types
type MessageType int

// Block contains the valid known MessageType values
const (
	MessageTypeDefault                               MessageType = 0
	MessageTypeRecipientAdd                          MessageType = 1
	MessageTypeRecipientRemove                       MessageType = 2
	MessageTypeCall                                  MessageType = 3
	MessageTypeChannelNameChange                     MessageType = 4
	MessageTypeChannelIconChange                     MessageType = 5
	MessageTypeChannelPinnedMessage                  MessageType = 6
	MessageTypeGuildMemberJoin                       MessageType = 7
	MessageTypeUserPremiumGuildSubscription          MessageType = 8
	MessageTypeUserPremiumGuildSubscriptionTierOne   MessageType = 9
	MessageTypeUserPremiumGuildSubscriptionTierTwo   MessageType = 10
	MessageTypeUserPremiumGuildSubscriptionTierThree MessageType = 11
	MessageTypeChannelFollowAdd                      MessageType = 12
	MessageTypeGuildDiscoveryDisqualified            MessageType = 14
	MessageTypeGuildDiscoveryRequalified             MessageType = 15
	MessageTypeThreadCreated                         MessageType = 18
	MessageTypeReply                                 MessageType = 19
	MessageTypeChatInputCommand                      MessageType = 20
	MessageTypeThreadStarterMessage                  MessageType = 21
	MessageTypeContextMenuCommand                    MessageType = 23
)

// A Message stores all data related to a specific Discord message.
type Message struct {
	// The ID of the channel in which the message was sent.
	ChannelID string `json:"channel_id"`

	// The ID of the guild in which the message was sent.
	GuildID string `json:"guild_id,omitempty"`

	// The content of the message.
	Content string `json:"content"`

	Author *User `json:"author"`
}

// UnmarshalJSON is a helper function to unmarshal the Message.
func (m *Message) UnmarshalJSON(data []byte) error {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary

	type message Message
	var v struct {
		message
		RawComponents []unmarshalableMessageComponent `json:"components"`
	}
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	*m = Message(v.message)
	return err
}

// GetCustomEmojis pulls out all the custom (Non-unicode) emojis from a message and returns a Slice of the Emoji struct.
func (m *Message) GetCustomEmojis() []*Emoji {
	var toReturn []*Emoji
	emojis := EmojiRegex.FindAllString(m.Content, -1)
	if len(emojis) < 1 {
		return toReturn
	}
	for _, em := range emojis {
		parts := strings.Split(em, ":")
		toReturn = append(toReturn, &Emoji{
			ID:       parts[2][:len(parts[2])-1],
			Name:     parts[1],
			Animated: strings.HasPrefix(em, "<a:"),
		})
	}
	return toReturn
}

// MessageFlags is the flags of "message" (see MessageFlags* consts)
// https://discord.com/developers/docs/resources/channel#message-object-message-flags
type MessageFlags int

// Valid MessageFlags values
const (
	// MessageFlagsCrossPosted This message has been published to subscribed channels (via Channel Following).
	MessageFlagsCrossPosted MessageFlags = 1 << 0
	// MessageFlagsIsCrossPosted this message originated from a message in another channel (via Channel Following).
	MessageFlagsIsCrossPosted MessageFlags = 1 << 1
	// MessageFlagsSuppressEmbeds do not include any embeds when serializing this message.
	MessageFlagsSuppressEmbeds MessageFlags = 1 << 2
	// TODO: deprecated, remove when compatibility is not needed
	MessageFlagsSupressEmbeds MessageFlags = 1 << 2
	// MessageFlagsSourceMessageDeleted the source message for this crosspost has been deleted (via Channel Following).
	MessageFlagsSourceMessageDeleted MessageFlags = 1 << 3
	// MessageFlagsUrgent this message came from the urgent message system.
	MessageFlagsUrgent MessageFlags = 1 << 4
	// MessageFlagsHasThread this message has an associated thread, with the same id as the message.
	MessageFlagsHasThread MessageFlags = 1 << 5
	// MessageFlagsEphemeral this message is only visible to the user who invoked the Interaction.
	MessageFlagsEphemeral MessageFlags = 1 << 6
	// MessageFlagsLoading this message is an Interaction Response and the bot is "thinking".
	MessageFlagsLoading MessageFlags = 1 << 7
	// MessageFlagsFailedToMentionSomeRolesInThread this message failed to mention some roles and add their members to the thread.
	MessageFlagsFailedToMentionSomeRolesInThread MessageFlags = 1 << 8
)

// File stores info about files you e.g. send in messages.
type File struct {
	Name        string
	ContentType string
	Reader      io.Reader
}

// MessageSend stores all parameters you can send with ChannelMessageSendComplex.
type MessageSend struct {
	Content         string                  `json:"content,omitempty"`
	Embeds          []*MessageEmbed         `json:"embeds"`
	TTS             bool                    `json:"tts"`
	Components      []MessageComponent      `json:"components"`
	Files           []*File                 `json:"-"`
	AllowedMentions *MessageAllowedMentions `json:"allowed_mentions,omitempty"`
	Reference       *MessageReference       `json:"message_reference,omitempty"`
	StickerIDs      []string                `json:"sticker_ids"`

	// TODO: Remove this when compatibility is not required.
	File *File `json:"-"`

	// TODO: Remove this when compatibility is not required.
	Embed *MessageEmbed `json:"-"`
}

// MessageEdit is used to chain parameters via ChannelMessageEditComplex, which
// is also where you should get the instance from.
type MessageEdit struct {
	Content         *string                 `json:"content,omitempty"`
	Components      []MessageComponent      `json:"components"`
	Embeds          []*MessageEmbed         `json:"embeds"`
	AllowedMentions *MessageAllowedMentions `json:"allowed_mentions,omitempty"`
	Flags           MessageFlags            `json:"flags,omitempty"`
	// Files to append to the message
	Files []*File `json:"-"`
	// Overwrite existing attachments
	Attachments *[]*MessageAttachment `json:"attachments,omitempty"`

	ID      string
	Channel string

	// TODO: Remove this when compatibility is not required.
	Embed *MessageEmbed `json:"-"`
}

// NewMessageEdit returns a MessageEdit struct, initialized
// with the Channel and ID.
func NewMessageEdit(channelID string, messageID string) *MessageEdit {
	return &MessageEdit{
		Channel: channelID,
		ID:      messageID,
	}
}

// SetContent is the same as setting the variable Content,
// except it doesn't take a pointer.
func (m *MessageEdit) SetContent(str string) *MessageEdit {
	m.Content = &str
	return m
}

// SetEmbed is a convenience function for setting the embed,
// so you can chain commands.
func (m *MessageEdit) SetEmbed(embed *MessageEmbed) *MessageEdit {
	m.Embeds = []*MessageEmbed{embed}
	return m
}

// SetEmbeds is a convenience function for setting the embeds,
// so you can chain commands.
func (m *MessageEdit) SetEmbeds(embeds []*MessageEmbed) *MessageEdit {
	m.Embeds = embeds
	return m
}

// AllowedMentionType describes the types of mentions used
// in the MessageAllowedMentions type.
type AllowedMentionType string

// The types of mentions used in MessageAllowedMentions.
const (
	AllowedMentionTypeRoles    AllowedMentionType = "roles"
	AllowedMentionTypeUsers    AllowedMentionType = "users"
	AllowedMentionTypeEveryone AllowedMentionType = "everyone"
)

// MessageAllowedMentions allows the user to specify which mentions
// Discord is allowed to parse in this message. This is useful when
// sending user input as a message, as it prevents unwanted mentions.
// If this type is used, all mentions must be explicitly whitelisted,
// either by putting an AllowedMentionType in the Parse slice
// (allowing all mentions of that type) or, in the case of roles and
// users, explicitly allowing those mentions on an ID-by-ID basis.
// For more information on this functionality, see:
// https://discordapp.com/developers/docs/resources/channel#allowed-mentions-object-allowed-mentions-reference
type MessageAllowedMentions struct {
	// The mention types that are allowed to be parsed in this message.
	// Please note that this is purposely **not** marked as omitempty,
	// so if a zero-value MessageAllowedMentions object is provided no
	// mentions will be allowed.
	Parse []AllowedMentionType `json:"parse"`

	// A list of role IDs to allow. This cannot be used when specifying
	// AllowedMentionTypeRoles in the Parse slice.
	Roles []string `json:"roles,omitempty"`

	// A list of user IDs to allow. This cannot be used when specifying
	// AllowedMentionTypeUsers in the Parse slice.
	Users []string `json:"users,omitempty"`

	// For replies, whether to mention the author of the message being replied to
	RepliedUser bool `json:"replied_user"`
}

// A MessageAttachment stores data for message attachments.
type MessageAttachment struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	ProxyURL    string `json:"proxy_url"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	Size        int    `json:"size"`
	Ephemeral   bool   `json:"ephemeral"`
}

// MessageEmbedFooter is a part of a MessageEmbed struct.
type MessageEmbedFooter struct {
	Text         string `json:"text,omitempty"`
	IconURL      string `json:"icon_url,omitempty"`
	ProxyIconURL string `json:"proxy_icon_url,omitempty"`
}

// MessageEmbedImage is a part of a MessageEmbed struct.
type MessageEmbedImage struct {
	URL      string `json:"url"`
	ProxyURL string `json:"proxy_url,omitempty"`
	Width    int    `json:"width,omitempty"`
	Height   int    `json:"height,omitempty"`
}

// MessageEmbedThumbnail is a part of a MessageEmbed struct.
type MessageEmbedThumbnail struct {
	URL      string `json:"url"`
	ProxyURL string `json:"proxy_url,omitempty"`
	Width    int    `json:"width,omitempty"`
	Height   int    `json:"height,omitempty"`
}

// MessageEmbedVideo is a part of a MessageEmbed struct.
type MessageEmbedVideo struct {
	URL    string `json:"url,omitempty"`
	Width  int    `json:"width,omitempty"`
	Height int    `json:"height,omitempty"`
}

// MessageEmbedProvider is a part of a MessageEmbed struct.
type MessageEmbedProvider struct {
	URL  string `json:"url,omitempty"`
	Name string `json:"name,omitempty"`
}

// MessageEmbedAuthor is a part of a MessageEmbed struct.
type MessageEmbedAuthor struct {
	URL          string `json:"url,omitempty"`
	Name         string `json:"name"`
	IconURL      string `json:"icon_url,omitempty"`
	ProxyIconURL string `json:"proxy_icon_url,omitempty"`
}

// MessageEmbedField is a part of a MessageEmbed struct.
type MessageEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

// An MessageEmbed stores data for message embeds.
type MessageEmbed struct {
	URL         string                 `json:"url,omitempty"`
	Type        EmbedType              `json:"type,omitempty"`
	Title       string                 `json:"title,omitempty"`
	Description string                 `json:"description,omitempty"`
	Timestamp   string                 `json:"timestamp,omitempty"`
	Color       int                    `json:"color,omitempty"`
	Footer      *MessageEmbedFooter    `json:"footer,omitempty"`
	Image       *MessageEmbedImage     `json:"image,omitempty"`
	Thumbnail   *MessageEmbedThumbnail `json:"thumbnail,omitempty"`
	Video       *MessageEmbedVideo     `json:"video,omitempty"`
	Provider    *MessageEmbedProvider  `json:"provider,omitempty"`
	Author      *MessageEmbedAuthor    `json:"author,omitempty"`
	Fields      []*MessageEmbedField   `json:"fields,omitempty"`
}

// EmbedType is the type of embed
// https://discord.com/developers/docs/resources/channel#embed-object-embed-types
type EmbedType string

// Block of valid EmbedTypes
const (
	EmbedTypeRich    EmbedType = "rich"
	EmbedTypeImage   EmbedType = "image"
	EmbedTypeVideo   EmbedType = "video"
	EmbedTypeGifv    EmbedType = "gifv"
	EmbedTypeArticle EmbedType = "article"
	EmbedTypeLink    EmbedType = "link"
)

// MessageReactions holds a reactions object for a message.
type MessageReactions struct {
	Count int    `json:"count"`
	Me    bool   `json:"me"`
	Emoji *Emoji `json:"emoji"`
}

// MessageActivity is sent with Rich Presence-related chat embeds
type MessageActivity struct {
	Type    MessageActivityType `json:"type"`
	PartyID string              `json:"party_id"`
}

// MessageActivityType is the type of message activity
type MessageActivityType int

// Constants for the different types of Message Activity
const (
	MessageActivityTypeJoin        MessageActivityType = 1
	MessageActivityTypeSpectate    MessageActivityType = 2
	MessageActivityTypeListen      MessageActivityType = 3
	MessageActivityTypeJoinRequest MessageActivityType = 5
)

// MessageApplication is sent with Rich Presence-related chat embeds
type MessageApplication struct {
	ID          string `json:"id"`
	CoverImage  string `json:"cover_image"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Name        string `json:"name"`
}

// MessageReference contains reference data sent with crossposted messages
type MessageReference struct {
	MessageID string `json:"message_id"`
	ChannelID string `json:"channel_id,omitempty"`
	GuildID   string `json:"guild_id,omitempty"`
}

// Reference returns MessageReference of given message
func (m *Message) Reference() *MessageReference {
	return &MessageReference{
		GuildID:   m.GuildID,
		ChannelID: m.ChannelID,
	}
}

// ContentWithMentionsReplaced will replace all @<id> mentions with the
// username of the mention.
func (m *Message) ContentWithMentionsReplaced() (content string) {
	return m.Content
}

var patternChannels = regexp.MustCompile("<#[^>]*>")

// ContentWithMoreMentionsReplaced will replace all @<id> mentions with the
// username of the mention, but also role IDs and more.
func (m *Message) ContentWithMoreMentionsReplaced(s *Session) (content string, err error) {
	return m.Content, nil
}

// MessageInteraction contains information about the application command interaction which generated the message.
type MessageInteraction struct {
	ID   string          `json:"id"`
	Type InteractionType `json:"type"`
	Name string          `json:"name"`
	User *User           `json:"user"`

	// Member is only present when the interaction is from a guild.
	Member *Member `json:"member"`
}
