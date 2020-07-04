package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"text/template"
	"time"

	humanize "github.com/dustin/go-humanize"
	gomail "gopkg.in/gomail.v2"
)

func init() {
	rand.Seed(time.Now().Unix())
}

type Mailer struct{}

func NewMailer() *Mailer {
	return &Mailer{}
}

func (m *Mailer) Forgot(email, secret string) error {
	subject := "Password reset link"

	params := struct {
		HTTPHost string
		Email    string
		Secret   string
	}{
		httpHost,
		email,
		secret,
	}
	return m.sendmail("forgot.html", email, subject, params)
}

func (m *Mailer) sendmail(tmpl, to, subject string, data interface{}) error {
	body, err := m.Render(tmpl, data)
	if err != nil {
		return err
	}

	cfg := config.FindInfo().Mail

	from := cfg.From
	server := cfg.Server
	port := cfg.Port
	username := cfg.Username
	password := cfg.Password

	if from == "" {
		from = fmt.Sprintf("Subspace <subspace@%s>", httpHost)
	}

	if server == "" {
		addrs, err := net.LookupMX(strings.Split(to, "@")[1])
		if err != nil || len(addrs) == 0 {
			return err
		}
		server = strings.TrimSuffix(addrs[rand.Intn(len(addrs))].Host, ".")
		port = 25
	}

	d := gomail.NewDialer(server, port, username, password)
	s, err := d.Dial()
	if err != nil {
		return err
	}
	logger.Infof("sendmail from %q to %q %q via %s:%d", from, to, subject, server, port)

	msg := gomail.NewMessage()
	msg.SetHeader("From", from)
	msg.SetHeader("To", to)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/html", body)

	if err := gomail.Send(s, msg); err != nil {
		return fmt.Errorf("failed sending email: %s", err)
	}
	return nil
}

func (m *Mailer) Render(target string, data interface{}) (string, error) {
	t := template.New(target).Funcs(template.FuncMap{
		"time": humanize.Time,
	})
	for _, filename := range AssetNames() {
		if !strings.HasPrefix(filename, "email/") {
			continue
		}
		name := strings.TrimPrefix(filename, "email/")
		b, err := Asset(filename)
		if err != nil {
			return "", err
		}

		var tmpl *template.Template
		if name == t.Name() {
			tmpl = t
		} else {
			tmpl = t.New(name)
		}
		if _, err := tmpl.Parse(string(b)); err != nil {
			return "", err
		}
	}
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}
