package destructoid

import (
  "fmt"
  "strings"
  "net/http"
  "io/ioutil"
  "bufio"
  "bytes"
  "encoding/json"
  "net/url"
  "regexp"
  "strconv"
  "github.com/steeve/broadcaster"
)

type servers struct {
  Cluster string `json:"cluster"`
  Servers []string `json:"servers"`
  WebsocketsServers []string `json:"websockets_servers"`
}

// TODO: Pass an array of preferred servers for reuse (to reduce number of server connections)
func chatServers(channel string) ([]string, error) {
  resp, err := http.Get("http://tmi.twitch.tv/servers?channel=" + url.QueryEscape(channel))
  if err != nil {
    return []string{}, err
  }

  defer resp.Body.Close()
  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    return []string{}, err
  }

  var response servers
  err = json.Unmarshal(body, &response)
  if err != nil {
    return []string{}, err
  }

  return response.Servers, nil
}

type Command struct {
  Tags string
  Command string
  From string
  To string
  Payload string
}

type User struct {
  Id int
  DisplayName string
  Name string
  Type string
  IsSub bool
  IsTurbo bool
  IsPrime bool
  IsMod bool
  IsGlobalMod bool
  IsAdmin bool
  IsStaff bool
}

type WhisperUser struct {
  Id int
  DisplayName string
  Name string
  Type string
  IsTurbo bool
  IsPrime bool
  IsGlobalMod bool
  IsAdmin bool
  IsStaff bool
}

type Sub struct {
  UserName string
  IsPrime bool
}

type Resub struct {
  User *User
  Text string
  Months int
}

type Channel struct {
  Id int
  Name string
}

type ChannelState struct {
  Channel string
  Language string
  IsEmoteOnly bool
  IsR9K bool
  IsSubOnly bool
  IsSlow bool
  SlowDuration int
}

type Message struct {
  Id string
  Channel *Channel
  User *User
  Text string
  Color string
  Timestamp int
}

type Whisper struct {
  Id string
  ThreadId string
  User *WhisperUser
  Text string
}

type Ban struct {
  Duration int
  User string
  Reason string
  IsPermanent bool
}

type ModState struct {
  UserName string
  IsMod bool
}

type Client struct {
  Raw *broadcaster.Broadcaster
  Command *broadcaster.Broadcaster
  Message *broadcaster.Broadcaster
  Ban *broadcaster.Broadcaster
  Join *broadcaster.Broadcaster
  ChannelState *broadcaster.Broadcaster
  ClearChat *broadcaster.Broadcaster
  ModState *broadcaster.Broadcaster
  Sub *broadcaster.Broadcaster
  Resub *broadcaster.Broadcaster
  Whispers *broadcaster.Broadcaster
  username string
  password string
  running chan bool
  sessions map[string]*Session
  messageExp *regexp.Regexp
  subExp *regexp.Regexp
}

func NewGuestClient() *Client {
  return NewClient("justinfan0", "")
}

func NewClient(username string, password string) *Client {
  c := &Client {
    Raw: broadcaster.NewBroadcaster(),
    Message: broadcaster.NewBroadcaster(),
    Command: broadcaster.NewBroadcaster(),
    Ban: broadcaster.NewBroadcaster(),
    Join: broadcaster.NewBroadcaster(),
    ChannelState: broadcaster.NewBroadcaster(),
    ClearChat: broadcaster.NewBroadcaster(),
    ModState: broadcaster.NewBroadcaster(),
    Sub: broadcaster.NewBroadcaster(),
    Resub: broadcaster.NewBroadcaster(),
    Whispers: broadcaster.NewBroadcaster(),
    username: username,
    password: password,
    sessions: make(map[string]*Session),
    messageExp: regexp.MustCompile("(@[^ ]+ +)?(:[^ ]+ +)([A-Z]+ +)([^ ]+)( .*)?"),
    subExp: regexp.MustCompile(":([^ ]+) just subscribed"),
  }

  return c
}

func (c *Client) Say(channel string, message string) {
  for _, session := range(c.sessions) {
    session.SendCommand("PRIVMSG #" + channel + " " + message)
  }
}

func (c *Client) Whisper(userName string, message string) {
  for _, session := range(c.sessions) {
    session.SendCommand("PRIVMSG #jtv :/w " + userName + " " + message)
  }
}

func (c *Client) Run() {
  <-c.running
}

func (c *Client) handleRaw(raw string) {
  parts := c.messageExp.FindStringSubmatch(raw)
  if len(parts) == 0 {
    return
  }

  c.Command.Broadcast(&Command{
    Tags: strings.TrimSuffix(parts[1], " "),
    From: strings.TrimSuffix(parts[2], " "),
    Command: strings.TrimSuffix(parts[3], " "),
    To: strings.TrimSuffix(parts[4], " "),
    Payload: strings.TrimSpace(parts[5]),
  })
}

func (c *Client) parseTags(spec string) map[string]string {
  tags := make(map[string]string)
  keyValues := strings.Split(spec, ";")
  for _, keyValue := range(keyValues) {
    parts := strings.Split(keyValue, "=")
    if len(parts) < 2 {
      continue
    }

    key := parts[0]
    value := parts[1]
    if key[0] == '@' && len(key) > 1 {
      key = key[1:]
    }

    tags[key] = value
  }

  return tags
}

func (c *Client) handlePrivMsg(command *Command) {
  if strings.HasPrefix(command.From, "twitchnotify!") {
    parts := c.subExp.FindStringSubmatch(command.Payload)
    if len(parts) >= 2 {
      c.Sub.Broadcast(&Sub{
        UserName: parts[1],
        IsPrime: strings.Contains(command.Payload, "Twitch Prime"),
      })
    }

    return
  }

  tags := c.parseTags(command.Tags)

  displayName := tags["display-name"]
  name := strings.Split(command.From, "!")[0][1:]
  if displayName == "" {
    displayName = name
  }

  var isPrime bool
  badges := strings.Split(tags["badges"], ",")
  for _, badge := range badges {
    if badge == "premium/1" {
      isPrime = true
      break
    }
  }

  var timestamp int
  var err error
  if timestamp, err = strconv.Atoi(tags["tmi-sent-ts"]); err != nil {
    timestamp = 0
  }

  var userId int
  if userId, err = strconv.Atoi(tags["user-id"]); err != nil {
    userId = 0
  }

  var channelId int
  if channelId, err = strconv.Atoi(tags["room-id"]); err != nil {
    channelId = 0
  }

  userType := tags["user-type"]

  c.Message.Broadcast(&Message{
    Id: tags["id"],
    Channel: &Channel {
      Id: channelId,
      Name: command.To[1:],
    },
    User: &User{
      Id: userId,
      DisplayName: displayName,
      Name: name,
      Type: userType,
      IsSub: tags["subscriber"] == "1",
      IsTurbo: tags["turbo"] == "1",
      IsPrime: isPrime,
      IsMod: userType == "mod",
      IsGlobalMod: userType == "global_mod",
      IsAdmin: userType == "admin",
      IsStaff: userType == "staff",
    },
    Text: command.Payload[1:],
    Color: tags["color"],
    Timestamp: timestamp,
  })
}

func (c *Client) handleUserNotice(command *Command) {
}

func (c *Client) handleClearChat(command *Command) {
  tags := c.parseTags(command.Tags)

  var duration int
  var err error

  banDuration := tags["ban-duration"]
  isPermanent := banDuration == ""
  if !isPermanent {
    if duration, err = strconv.Atoi(banDuration); err != nil {
      duration = 0
    }
  }

  if len(command.Payload) > 1 {
    c.Ban.Broadcast(&Ban{
      Duration: duration,
      User: command.Payload[1:],
      Reason: tags["ban-reason"],
      IsPermanent: isPermanent,
    })
  } else {
    c.ClearChat.Broadcast(command.To[1:])
  }
}

func (c *Client) handleRoomState(command *Command) {
  tags := c.parseTags(command.Tags)

  var slowDuration int
  var err error
  if slowDuration, err = strconv.Atoi(tags["slow"]); err != nil {
    slowDuration = 0
  }

  c.ChannelState.Broadcast(&ChannelState{
    Channel: command.To[1:],
    Language: tags["broadcaster-lang"],
    IsEmoteOnly: tags["emote-only"] == "1",
    IsR9K: tags["r9k"] == "1",
    IsSubOnly: tags["subs-only"] == "1",
    IsSlow: slowDuration != 0,
    SlowDuration: slowDuration,
  })
}

func (c *Client) handleJoin(command *Command) {
  c.Join.Broadcast(command.To[1:])
}

func (c *Client) handleMode(command *Command) {
  if len(command.Payload) <= 4 {
    return
  }

  op := command.Payload[0:2]
  if op == "+o" {
    c.ModState.Broadcast(&ModState{
      UserName: command.Payload[3:],
      IsMod: true,
    })
  } else if op == "-o" {
    c.ModState.Broadcast(&ModState{
      UserName: command.Payload[3:],
      IsMod: false,
    })
  }
}

func (c *Client) handleWhisper(command *Command) {
  tags := c.parseTags(command.Tags)

  displayName := tags["display-name"]
  name := strings.Split(command.From, "!")[0][1:]
  if displayName == "" {
    displayName = name
  }

  var isPrime bool
  badges := strings.Split(tags["badges"], ",")
  for _, badge := range badges {
    if badge == "premium/1" {
      isPrime = true
      break
    }
  }

  var userId int
  var err error
  if userId, err = strconv.Atoi(tags["user-id"]); err != nil {
    userId = 0
  }

  userType := tags["user-type"]

  c.Whispers.Broadcast(&Whisper{
    Id: tags["message-id"],
    ThreadId: tags["thread-id"],
    User: &WhisperUser{
      Id: userId,
      DisplayName: displayName,
      Name: name,
      Type: userType,
      IsTurbo: tags["turbo"] == "1",
      IsPrime: isPrime,
      IsGlobalMod: userType == "global_mod",
      IsAdmin: userType == "admin",
      IsStaff: userType == "staff",
    },
    Text: command.Payload[1:],
  })
}

func (c *Client) handleCommand(command *Command) {
  switch command.Command {
  case "PRIVMSG":
    c.handlePrivMsg(command)
  case "CLEARCHAT":
    c.handleClearChat(command)
  case "JOIN":
    c.handleJoin(command)
  case "ROOMSTATE":
    c.handleRoomState(command)
  case "MODE":
    c.handleMode(command)
  case "USERNOTICE":
    c.handleUserNotice(command)
  case "WHISPER":
    c.handleWhisper(command)
  }
}

func dropCR(data []byte) []byte {
  if len(data) > 0 && data[len(data)-1] == '\r' {
    return data[0 : len(data)-1]
  }
  return data
}

func scanCRLF(data []byte, eof bool) (advance int, token []byte, err error) {
  if eof && len(data) == 0 {
    return 0, nil, nil
  }

  if i := bytes.Index(data, []byte{'\r','\n'}); i >= 0 {
    return i + 2, dropCR(data[0:i]), nil
  }

  if eof {
    return len(data), dropCR(data), nil
  }

  return 0, nil, nil
}

func (c *Client) connect(server string) *Session {
  session := Connect(server, c.username, c.password)
  scanner := bufio.NewScanner(session.conn)
  scanner.Split(scanCRLF)

  go func() {
    read, done := c.Command.Listen()
    defer close(done)

    for {
      command := (<-read).(*Command)
      c.handleCommand(command)
    }
  }()

  go func() {
    read, done := c.Raw.Listen()
    defer close(done)

    for {
      raw := (<-read).(string)
      c.handleRaw(raw)
    }
  }()

  go func() {
    for scanner.Scan() {
      raw := scanner.Text()
      c.Raw.Broadcast(raw)
    }
  }()

  return session
}

func (c *Client) JoinChannel(channel string) {
  channel = strings.ToLower(strings.TrimSpace(channel))
  if len(channel) == 0 {
    return
  }

  servers, err := chatServers(channel)
  if err != nil {
    panic(err)
  }

  server := servers[0]
  fmt.Printf("%s is hosted on %s\n", channel, server)

  var session *Session
  var ok bool
  if session, ok = c.sessions[server]; !ok {
    session = c.connect(server)
    c.sessions[server] = session
  }

  // TODO: Connect to group chat cluster for whispers.
  // http://tmi.twitch.tv/servers?cluster=group
  // c.connect("irc.chat.twitch.tv:6667")

  session.join(channel)
}

func (c *Client) OnRaw(handler func (raw string)) {
  go func() {
    read, done := c.Raw.Listen()
    defer close(done)

    for {
      raw := (<-read).(string)
      handler(raw)
    }
  }()
}

func (c *Client) OnMessage(handler func (message *Message)) {
  go func() {
    read, done := c.Message.Listen()
    defer close(done)

    for {
      message := (<-read).(*Message)
      handler(message)
    }
  }()
}

func (c *Client) OnBan(handler func (ban *Ban)) {
  go func() {
    read, done := c.Ban.Listen()
    defer close(done)

    for {
      ban := (<-read).(*Ban)
      handler(ban)
    }
  }()
}

func (c *Client) OnJoin(handler func (channel string)) {
  go func() {
    read, done := c.Join.Listen()
    defer close(done)

    for {
      channel := (<-read).(string)
      handler(channel)
    }
  }()
}

func (c *Client) OnChannelState(handler func (state *ChannelState)) {
  go func() {
    read, done := c.ChannelState.Listen()
    defer close(done)

    for {
      state := (<-read).(*ChannelState)
      handler(state)
    }
  }()
}

func (c *Client) OnClearChat(handler func (channel string)) {
  go func() {
    read, done := c.ClearChat.Listen()
    defer close(done)

    for {
      channel := (<-read).(string)
      handler(channel)
    }
  }()
}

func (c *Client) OnModState(handler func (state *ModState)) {
  go func() {
    read, done := c.ModState.Listen()
    defer close(done)

    for {
      state := (<-read).(*ModState)
      handler(state)
    }
  }()
}

func (c *Client) OnSub(handler func (sub *Sub)) {
  go func() {
    read, done := c.Sub.Listen()
    defer close(done)

    for {
      sub := (<-read).(*Sub)
      handler(sub)
    }
  }()
}

func (c *Client) OnWhisper(handler func (whisper *Whisper)) {
  go func() {
    read, done := c.Whispers.Listen()
    defer close(done)

    for {
      whisper := (<-read).(*Whisper)
      handler(whisper)
    }
  }()
}
