package destructoid

import (
  "fmt"
  "log"
  "strings"
  "time"
  "net"
)

type Session struct {
  conn net.Conn
}

func Connect(server string, username string, password string) *Session {
  fmt.Printf("Connecting to %s.\n", server)

  conn, err := net.Dial("tcp", server)
  if err != nil {
    log.Fatal("Cannot connect to IRC server: ", err)
    return nil
  }

  fmt.Printf("Connected to %s.\n", server)

  session := &Session {
    conn: conn,
  }

  session.login(username, password)

  return session
}

func (s *Session) SendCommand(command string) {
  fmt.Fprintf(s.conn, "%s\r\n", command)
}

func (s *Session) sendPongs() {
  for {
    time.Sleep(10 * time.Second);
    s.SendCommand("PONG tmi.twitch.tv")
  }
}

func (s *Session) login(username string, password string) {
  username = strings.ToLower(username)

  if !strings.HasPrefix(strings.ToLower(password), "oauth:") {
    password = "oauth:" + password
  }

  if password != "" {
    s.SendCommand("PASS " + password)
  }

  s.SendCommand("USER " + username)
  s.SendCommand("NICK " + username)
  s.SendCommand("CAP REQ :twitch.tv/tags")
  s.SendCommand("CAP REQ :twitch.tv/commands")
  s.SendCommand("CAP REQ :twitch.tv/membership")

  go s.sendPongs()
}

func (s *Session) join(channel string) {
  if len(channel) < 1 {
    return
  }

  if channel[0] != '#' {
    channel = "#" + channel
  }

  fmt.Printf("Joining %s\n", channel)
  s.SendCommand("JOIN " + channel)
}
