package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"

	qrcode "github.com/skip2/go-qrcode"
)

var (
	validEmail         = regexp.MustCompile(`^[ -~]+@[ -~]+$`)
	validPassword      = regexp.MustCompile(`^[ -~]{6,200}$`)
	validString        = regexp.MustCompile(`^[ -~]{1,200}$`)
	maxProfiles        = 250
	maxProfilesPerUser = 10
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func ssoHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if token := samlSP.GetAuthorizationToken(r); token != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	logger.Debugf("SSO: require account handler")
	samlSP.RequireAccountHandler(w, r)
}

func samlHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if samlSP == nil {
		logger.Warnf("SAML is not configured")
		http.NotFound(w, r)
		return
	}
	logger.Debugf("SSO: samlSP.ServeHTTP")
	samlSP.ServeHTTP(w, r)
}

func wireguardQRConfigHandler(w *Web) {
	profile, err := config.FindProfile(w.ps.ByName("profile"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin && profile.UserID != w.User.ID {
		Error(w.w, fmt.Errorf("failed to view config: permission denied"))
		return
	}

	b, err := ioutil.ReadFile(profile.WireGuardConfigPath())
	if err != nil {
		Error(w.w, err)
		return
	}

	img, err := qrcode.Encode(string(b), qrcode.Medium, 256)
	if err != nil {
		Error(w.w, err)
		return
	}

	w.w.Header().Set("Content-Type", "image/png")
	w.w.Header().Set("Content-Length", fmt.Sprintf("%d", len(img)))
	if _, err := w.w.Write(img); err != nil {
		Error(w.w, err)
		return
	}
}

func wireguardConfigHandler(w *Web) {
	profile, err := config.FindProfile(w.ps.ByName("profile"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin && profile.UserID != w.User.ID {
		Error(w.w, fmt.Errorf("failed to view config: permission denied"))
		return
	}

	b, err := ioutil.ReadFile(profile.WireGuardConfigPath())
	if err != nil {
		Error(w.w, err)
		return
	}

	w.w.Header().Set("Content-Disposition", "attachment; filename="+profile.WireGuardConfigName())
	w.w.Header().Set("Content-Type", "application/x-wireguard-profile")
	w.w.Header().Set("Content-Length", fmt.Sprintf("%d", len(b)))
	if _, err := w.w.Write(b); err != nil {
		Error(w.w, err)
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

	if err := w.SigninSession(true, ""); err != nil {
		Error(w.w, err)
		return
	}
	w.Redirect("/settings?success=configured")
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

	if err := w.SigninSession(true, ""); err != nil {
		Error(w.w, err)
		return
	}
	w.Redirect("/")
}

func signoutHandler(w *Web) {
	w.SignoutSession()
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
	if err := w.SigninSession(true, ""); err != nil {
		Error(w.w, err)
		return
	}

	w.Redirect("/")
}

func userEditHandler(w *Web) {
	userID := w.ps.ByName("user")
	if userID == "" {
		userID = w.r.FormValue("user")
	}
	user, err := config.FindUser(userID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin {
		Error(w.w, fmt.Errorf("failed to edit user: permission denied"))
		return
	}

	if w.r.Method == "GET" {
		w.TargetUser = user
		w.Profiles = config.ListProfilesByUser(user.ID)
		w.HTML()
		return
	}

	if w.User.ID == user.ID {
		w.Redirect("/user/edit/%s", user.ID)
		return
	}

	admin := w.r.FormValue("admin") == "yes"

	config.UpdateUser(user.ID, func(u *User) error {
		u.Admin = admin
		return nil
	})

	w.Redirect("/user/edit/%s?success=edituser", user.ID)
}

func userDeleteHandler(w *Web) {
	userID := w.ps.ByName("user")
	if userID == "" {
		userID = w.r.FormValue("user")
	}
	user, err := config.FindUser(userID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin {
		Error(w.w, fmt.Errorf("failed to delete user: permission denied"))
		return
	}
	if w.User.ID == user.ID {
		w.Redirect("/user/edit/%s?error=deleteuser", user.ID)
		return
	}

	if w.r.Method == "GET" {
		w.TargetUser = user
		w.HTML()
		return
	}

	for _, profile := range config.ListProfilesByUser(user.ID) {
		if err := deleteProfile(profile); err != nil {
			logger.Errorf("delete profile failed: %s", err)
			w.Redirect("/profile/delete?error=deleteprofile")
			return
		}
	}

	if err := config.DeleteUser(user.ID); err != nil {
		Error(w.w, err)
		return
	}
	w.Redirect("/?success=deleteuser")
}

func profileAddHandler(w *Web) {
	if !w.Admin && w.User.ID == "" {
		http.NotFound(w.w, w.r)
		return
	}

	name := strings.TrimSpace(w.r.FormValue("name"))
	platform := strings.TrimSpace(w.r.FormValue("platform"))
	admin := w.r.FormValue("admin") == "yes"

	if platform == "" {
		platform = "other"
	}

	if name == "" {
		w.Redirect("/?error=profilename")
		return
	}

	var userID string
	if admin {
		userID = ""
	} else {
		userID = w.User.ID
	}

	if !admin {
		if len(config.ListProfilesByUser(userID)) >= maxProfilesPerUser {
			w.Redirect("/?error=addprofile")
			return
		}
	}

	if len(config.ListProfiles()) >= maxProfiles {
		w.Redirect("/?error=addprofile")
		return
	}

	profile, err := config.AddProfile(userID, name, platform)
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
	listenport := "51820"
	if port := getEnv("SUBSPACE_LISTENPORT", "nil"); port != "nil" {
		listenport = port
	}
	endpointHost := httpHost
	if eh := getEnv("SUBSPACE_ENDPOINT_HOST", "nil"); eh != "nil" {
		endpointHost = eh
	}
	allowedips := "0.0.0.0/0, ::/0"
	if ips := getEnv("SUBSPACE_ALLOWED_IPS", "nil"); ips != "nil" {
		allowedips = ips
	}

	script := `
cd {{$.Datadir}}/wireguard
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
Address = {{$.IPv4Pref}}{{$.Profile.Number}}/{{$.IPv4Cidr}},{{$.IPv6Pref}}{{$.Profile.Number}}/{{$.IPv6Cidr}}

[Peer]
PublicKey = $(cat server.public)

Endpoint = {{$.EndpointHost}}:{{$.Listenport}}
AllowedIPs = {{$.AllowedIPS}}
WGCLIENT
`
	_, err = bash(script, struct {
		Profile      Profile
		EndpointHost string
		Datadir      string
		IPv4Gw       string
		IPv6Gw       string
		IPv4Pref     string
		IPv6Pref     string
		IPv4Cidr     string
		IPv6Cidr     string
		Listenport   string
		AllowedIPS   string
	}{
		profile,
		endpointHost,
		datadir,
		ipv4Gw,
		ipv6Gw,
		ipv4Pref,
		ipv6Pref,
		ipv4Cidr,
		ipv6Cidr,
		listenport,
		allowedips,
	})
	if err != nil {
		logger.Warn(err)
		f, _ := os.Create("/tmp/error.txt")
		errstr := fmt.Sprintln(err)
		f.WriteString(errstr)
		w.Redirect("/?error=addprofile")
		return
	}

	w.Redirect("/profile/connect/%s?success=addprofile", profile.ID)
}

func profileConnectHandler(w *Web) {
	profile, err := config.FindProfile(w.ps.ByName("profile"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin && profile.UserID != w.User.ID {
		Error(w.w, fmt.Errorf("failed to view profile: permission denied"))
		return
	}
	w.Profile = profile
	w.HTML()
}

func profileDeleteHandler(w *Web) {
	profileID := w.ps.ByName("profile")
	if profileID == "" {
		profileID = w.r.FormValue("profile")
	}
	profile, err := config.FindProfile(profileID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin && profile.UserID != w.User.ID {
		Error(w.w, fmt.Errorf("failed to delete profile: permission denied"))
		return
	}

	if w.r.Method == "GET" {
		w.Profile = profile
		w.HTML()
		return
	}
	if err := deleteProfile(profile); err != nil {
		logger.Errorf("delete profile failed: %s", err)
		w.Redirect("/profile/delete?error=deleteprofile")
		return
	}
	if profile.UserID != "" {
		w.Redirect("/user/edit/%s?success=deleteprofile", profile.UserID)
		return
	}
	w.Redirect("/?success=deleteprofile")
}

func indexHandler(w *Web) {
	if w.User.ID != "" {
		w.TargetProfiles = config.ListProfilesByUser(w.User.ID)
	}
	if w.Admin {
		w.Profiles = config.ListProfilesByUser("")
		w.Users = config.ListUsers()
	} else {
		w.Profiles = config.ListProfilesByUser(w.User.ID)
	}
	w.HTML()
}

func settingsHandler(w *Web) {
	if !w.Admin {
		Error(w.w, fmt.Errorf("settings: permission denied"))
		return
	}

	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	samlMetadata := strings.TrimSpace(w.r.FormValue("saml_metadata"))

	currentPassword := w.r.FormValue("current_password")
	newPassword := w.r.FormValue("new_password")

	config.UpdateInfo(func(i *Info) error {
		i.SAML.IDPMetadata = samlMetadata
		i.Email = email
		return nil
	})

	// Configure SAML if metadata is present.
	if len(samlMetadata) > 0 {
		if err := configureSAML(); err != nil {
			logger.Warnf("configuring SAML failed: %s", err)
			w.Redirect("/settings?error=saml")
		}
	} else {
		samlSP = nil
	}

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
			i.Password = hashedPassword
			return nil
		})
	}

	w.Redirect("/settings?success=settings")
}

func helpHandler(w *Web) {
	w.HTML()
}

//
// Helpers
//
func deleteProfile(profile Profile) error {
	script := `
# WireGuard
cd {{$.Datadir}}/wireguard
peerid=$(cat peers/{{$.Profile.ID}}.conf | awk '/PublicKey/ { printf("%s", $3) }' )
wg set wg0 peer $peerid remove
rm peers/{{$.Profile.ID}}.conf
rm clients/{{$.Profile.ID}}.conf
`
	output, err := bash(script, struct {
		Datadir string
		Profile Profile
	}{
		datadir,
		profile,
	})
	if err != nil {
		return fmt.Errorf("delete profile failed %s %s", err, output)
	}
	return config.DeleteProfile(profile.ID)
}
