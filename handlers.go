package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var (
	validEmail    = regexp.MustCompile(`^[ -~]+@[ -~]+$`)
	validPassword = regexp.MustCompile(`^[ -~]{6,200}$`)
	validString   = regexp.MustCompile(`^[ -~]{1,200}$`)
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func wireguardConfigHandler(w *Web) {
	profile, err := config.FindProfile(w.ps.ByName("profile"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	f, err := os.Open(profile.WireGuardConfigPath())
	if err != nil {
		logger.Warn(err)
		Error(w.w, fmt.Errorf("config file error"))
		return
	}

	stat, err := f.Stat()
	if err != nil {
		logger.Warn(err)
		Error(w.w, fmt.Errorf("config file size error"))
		return
	}

	w.w.Header().Set("Content-Disposition", "attachment; filename="+profile.WireGuardConfigName())
	w.w.Header().Set("Content-Type", "application/x-wireguard-profile")
	w.w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	_, err = io.Copy(w.w, f)
	if err != nil {
		logger.Error(err)
		Error(w.w, fmt.Errorf("config output error"))
		return
	}
}

func configureHandler(w *Web) {
	if config.FindInfo().Configured {
		w.Redirect("/?error=configured")
		return
	}

	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	emailConfirm := strings.ToLower(strings.TrimSpace(w.r.FormValue("email_confirm")))
	password := w.r.FormValue("password")

	if !validEmail.MatchString(email) || !validPassword.MatchString(password) || email != emailConfirm {
		w.Redirect("/configure?error=invalid")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Redirect("/forgot?error=bcrypt")
		return
	}
	config.UpdateInfo(func(i *Info) error {
		i.Email = email
		i.Password = hashedPassword
		i.Configured = true
		return nil
	})

	sessionCookie, err := NewSessionCookie(w.r)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)
	w.Redirect("/")
	return
}

func forgotHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	secret := w.r.FormValue("secret")
	password := w.r.FormValue("password")

	if email != "" && !validEmail.MatchString(email) {
		w.Redirect("/forgot?error=invalid")
		return
	}
	if secret != "" && !validString.MatchString(secret) {
		w.Redirect("/forgot?error=invalid")
		return
	}
	if email != "" && secret != "" && !validPassword.MatchString(password) {
		w.Redirect("/forgot?error=invalid&email=%s&secret=%s", email, secret)
		return
	}

	if email != config.FindInfo().Email {
		w.Redirect("/forgot?error=invalid")
		return
	}

	if secret == "" {
		secret = config.FindInfo().Secret
		if secret == "" {
			secret = RandomString(32)
			config.UpdateInfo(func(i *Info) error {
				if i.Secret == "" {
					i.Secret = secret
				}
				return nil
			})
		}

		go func() {
			if err := mailer.Forgot(email, secret); err != nil {
				logger.Error(err)
			}
		}()

		w.Redirect("/forgot?success=forgot")
		return
	}

	if secret != config.FindInfo().Secret {
		w.Redirect("/forgot?error=invalid")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Redirect("/forgot?error=bcrypt")
		return
	}
	config.UpdateInfo(func(i *Info) error {
		i.Password = hashedPassword
		i.Secret = ""
		return nil
	})

	sessionCookie, err := NewSessionCookie(w.r)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)
	w.Redirect("/")
	return
}

func signoutHandler(w *Web) {
	http.SetCookie(w.w, NewDeletionCookie())
	w.Redirect("/signin")
}

func signinHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	password := w.r.FormValue("password")

	if email != config.FindInfo().Email {
		w.Redirect("/signin?error=invalid")
		return
	}

	if err := bcrypt.CompareHashAndPassword(config.FindInfo().Password, []byte(password)); err != nil {
		w.Redirect("/signin?error=invalid")
		return
	}
	sessionCookie, err := NewSessionCookie(w.r)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)

	w.Redirect("/")
}

func addProfileHandler(w *Web) {
	name := strings.TrimSpace(w.r.FormValue("name"))
	platform := strings.TrimSpace(w.r.FormValue("platform"))

	if platform == "" {
		platform = "other"
	}

	if name == "" {
		w.Redirect("/?error=profilename")
		return
	}

	profile, err := config.AddProfile(name, platform)
	if err != nil {
		logger.Warn(err)
		w.Redirect("/?error=addprofile")
		return
	}

	ipv4Pref := "10.99.97."
	if pref := getEnv("SUBSPACE_IPV4_PREF", "nil"); pref != "nil" {
		ipv4Pref = pref
	}
	ipv4Gw := "10.99.97.1"
	if gw := getEnv("SUBSPACE_IPV4_GW", "nil"); gw != "nil" {
		ipv4Gw = gw
	}
	ipv4Cidr := "24"
	if cidr := getEnv("SUBSPACE_IPV4_CIDR", "nil"); cidr != "nil" {
		ipv4Cidr = cidr
	}

	ipv6Pref := "fd00::10:97:"
	if pref := getEnv("SUBSPACE_IPV6_PREF", "nil"); pref != "nil" {
		ipv6Pref = pref
	}
	ipv6Gw := "fd00::10:97:1"
	if gw := getEnv("SUBSPACE_IPV6_GW", "nil"); gw != "nil" {
		ipv6Gw = gw
	}
	ipv6Cidr := "64"
	if cidr := getEnv("SUBSPACE_IPV6_CIDR", "nil"); cidr != "nil" {
		ipv6Cidr = cidr
	}

	script := `
cd /data/wireguard
wg_private_key="$(wg genkey)"
wg_public_key="$(echo $wg_private_key | wg pubkey)"

wg set wg0 peer ${wg_public_key} allowed-ips {{$.IPv4Pref}}{{$.Profile.Number}}/32,{{$.IPv6Pref}}{{$.Profile.Number}}/128

cat <<WGPEER >peers/{{$.Profile.ID}}.conf
[Peer]
PublicKey = ${wg_public_key}
AllowedIPs = {{$.IPv4Pref}}{{$.Profile.Number}}/32,{{$.IPv6Pref}}{{$.Profile.Number}}/128
WGPEER

cat <<WGCLIENT >clients/{{$.Profile.ID}}.conf
[Interface]
PrivateKey = ${wg_private_key}
DNS = {{$.IPv4Gw}}, {{$.IPv6Gw}}
Address = {{$.IPv4Pref}}{{$.Profile.Number}}/{{$.IPv4Pref}},{{$.IPv6Pref}}{{$.Profile.Number}}/{{$.IPv6Cidr}}

[Peer]
PublicKey = $(cat server.public)
Endpoint = {{$.Domain}}:51820
AllowedIPs = 0.0.0.0/0, ::/0
WGCLIENT
`
	_, err = bash(script, struct {
		Profile  Profile
		Domain   string
		IPv4Gw   string
		IPv6Gw   string
		IPv4Pref string
		IPv6Pref string
		IPv4Cidr string
		IPv6Cidr string
	}{
		profile,
		httpHost,
		ipv4Gw,
		ipv6Gw,
		ipv4Pref,
		ipv6Pref,
		ipv4Cidr,
		ipv6Cidr,
	})
	if err != nil {
		logger.Warn(err)
		f, _ := os.Create("/tmp/error.txt")
		errstr := fmt.Sprintln(err)
		f.WriteString(errstr)
		w.Redirect("/?error=addprofile")
		return
	}

	w.Redirect("/profiles/connect/%s?success=addprofile", profile.ID)
}

func connectProfileHandler(w *Web) {
	profile, err := config.FindProfile(w.ps.ByName("profile"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	w.Profile = profile
	w.HTML()
	return
}

func deleteProfileHandler(w *Web) {
	profileID := w.ps.ByName("profile")
	if profileID == "" {
		profileID = w.r.FormValue("profile")
	}
	profile, err := config.FindProfile(profileID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	if w.r.Method == "GET" {
		w.Profile = profile
		w.HTML()
		return
	}

	script := `
# WireGuard
cd /data/wireguard
peerid=$(cat peers/{{$.Profile.ID}}.conf | perl -ne 'print $1 if /PublicKey\s*=\s*(.*)/')
wg set wg0 peer $peerid remove
rm peers/{{$.Profile.ID}}.conf
rm clients/{{$.Profile.ID}}.conf
`
	output, err := bash(script, struct {
		Profile Profile
	}{
		profile,
	})
	if err != nil {
		logger.Warnf("delete profile failed %s %s", err, output)
		w.Redirect("/profiles/delete?error=removeprofile")
		return
	}

	if err := config.DeleteProfile(profile.ID); err != nil {
		panic(err)
	}
	w.Redirect("/?success=removeprofile")
}

func indexHandler(w *Web) {
	profiles := config.ListProfiles()

	w.Profiles = profiles
	w.HTML()
}

func settingsHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	currentPassword := w.r.FormValue("current_password")
	newPassword := w.r.FormValue("new_password")

	if currentPassword != "" || newPassword != "" {
		if !validPassword.MatchString(newPassword) {
			w.Redirect("/settings?error=invalid")
			return
		}

		if err := bcrypt.CompareHashAndPassword(config.FindInfo().Password, []byte(currentPassword)); err != nil {
			w.Redirect("/settings?error=invalid")
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			w.Redirect("/settings?error=bcrypt")
			return
		}

		config.UpdateInfo(func(i *Info) error {
			i.Email = email
			i.Password = hashedPassword
			return nil
		})
	}

	config.UpdateInfo(func(i *Info) error {
		i.Email = email
		return nil
	})

	w.Redirect("/?success=settings")
}

func helpHandler(w *Web) {
	w.HTML()
}
