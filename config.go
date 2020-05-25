package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

var (
	ErrProfileNotFound  = errors.New("profile not found")
	ErrUserNotFound     = errors.New("user not found")
	ErrUserDeleteFailed = errors.New("delete failed because user has devices")
)

type User struct {
	ID      string    `json:"id"`
	Email   string    `json:"email"`
	Admin   bool      `json:"admin"`
	Created time.Time `json:"created"`

	Profiles []Profile `json:"-"`
}

type Profile struct {
	ID       string    `json:"id"`
	UserID   string    `json:"user"`
	Name     string    `json:"name"`
	Platform string    `json:"platform"`
	Number   int       `json:"number"`
	Created  time.Time `json:"created"`

	User User `json:"-"`
}

func (p Profile) NameClean() string {
	return regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(p.Name, "")
}

func (p Profile) WireGuardConfigPath() string {
	return fmt.Sprintf("%s/wireguard/clients/%s.conf", datadir, p.ID)
}

func (p Profile) WireGuardConfigName() string {
	return "wg0.conf"
}

type Info struct {
	Email      string `json:"email"`
	Password   []byte `json:"password"`
	Secret     string `json:"secret"`
	Configured bool   `json:"configure"`
	Domain     string `json:"domain"`
	HashKey    string `json:"hash_key"`
	BlockKey   string `json:"block_key"`
	SAML       struct {
		IDPMetadata string `json:"idp_metadata"`
		PrivateKey  []byte `json:"private_key"`
		Certificate []byte `json:"certificate"`
	} `json:"saml"`
	Mail struct {
		From     string `json:"from"`
		Server   string `json:"server"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"mail"`
}

type Config struct {
	mu       sync.RWMutex
	filename string

	Info *Info `json:"info"`

	Profiles []*Profile `json:"profiles"`
	Users    []*User    `json:"users"`

	Modified time.Time `json:"modified"`
}

func NewConfig(filename string) (*Config, error) {
	filename = filepath.Join(datadir, filename)
	c := &Config{filename: filename}
	b, err := ioutil.ReadFile(filename)

	// Create new config with defaults
	if os.IsNotExist(err) {
		c.Info = &Info{
			HashKey:  RandomString(32),
			BlockKey: RandomString(32),
		}
		return c, c.generateSAMLKeyPair()
	}
	if err != nil {
		return nil, err
	}

	// Open existing config
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("invalid config %q: %s", filename, err)
	}

	return c, nil
}

func (c *Config) Lock() {
	c.mu.Lock()
}

func (c *Config) Unlock() {
	c.mu.Unlock()
}

func (c *Config) RLock() {
	c.mu.RLock()
}

func (c *Config) RUnlock() {
	c.mu.RUnlock()
}

func (c *Config) generateSAMLKeyPair() error {
	// Generate private key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Generate the certificate.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	tmpl := x509.Certificate{
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   httpHost,
			Organization: []string{"Subspace"},
		},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}

	// Generate private key PEM block.
	c.Info.SAML.PrivateKey = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	// Generate certificate PEM block.
	c.Info.SAML.Certificate = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	return c.save()
}

func (c *Config) DeleteProfile(id string) error {
	c.Lock()
	defer c.Unlock()

	var profiles []*Profile
	for _, p := range c.Profiles {
		if p.ID == id {
			continue
		}
		profiles = append(profiles, p)
	}
	c.Profiles = profiles
	return c.save()
}

func (c *Config) UpdateProfile(id string, fn func(*Profile) error) error {
	c.Lock()
	defer c.Unlock()
	p, err := c.findProfile(id)
	if err != nil {
		return err
	}
	if err := fn(p); err != nil {
		return err
	}
	return c.save()
}

func (c *Config) AddProfile(userID, name, platform string) (Profile, error) {
	c.Lock()
	defer c.Unlock()

	id := RandomString(16)

	number := 2 // MUST start at 2
	for _, p := range c.Profiles {
		if p.Number >= number {
			number = p.Number + 1
		}
	}
	profile := Profile{
		ID:       id,
		UserID:   userID,
		Name:     name,
		Platform: platform,
		Number:   number,
		Created:  time.Now(),
	}
	c.Profiles = append(c.Profiles, &profile)
	return profile, c.save()
}

func (c *Config) FindProfile(id string) (Profile, error) {
	c.RLock()
	defer c.RUnlock()
	u, err := c.findProfile(id)
	if err != nil {
		return Profile{}, err
	}
	return *u, nil
}

func (c *Config) findProfile(id string) (*Profile, error) {
	for _, u := range c.Profiles {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, ErrProfileNotFound
}

func (c *Config) ListProfilesByUser(id string) (profiles []Profile) {
	c.RLock()
	defer c.RUnlock()
	for _, p := range c.listProfilesByUser(id) {
		profiles = append(profiles, *p)
	}
	return
}

func (c *Config) listProfilesByUser(id string) (profiles []*Profile) {
	for _, p := range c.Profiles {
		if p.UserID != id {
			continue
		}
		profiles = append(profiles, p)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Created.After(profiles[j].Created) })
	return
}

func (c *Config) ListProfiles() (profiles []Profile) {
	c.RLock()
	defer c.RUnlock()
	for _, p := range c.listProfiles() {
		profiles = append(profiles, *p)
	}
	return
}

func (c *Config) listProfiles() (profiles []*Profile) {
	profiles = append(profiles, c.Profiles...)
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Created.After(profiles[j].Created) })
	return
}

func (c *Config) FindInfo() Info {
	c.RLock()
	defer c.RUnlock()
	return *c.Info
}

func (c *Config) UpdateInfo(fn func(*Info) error) error {
	c.Lock()
	defer c.Unlock()
	if err := fn(c.Info); err != nil {
		return err
	}
	return c.save()
}

func (c *Config) DeleteUser(id string) error {
	c.Lock()
	defer c.Unlock()

	if len(c.listProfilesByUser(id)) > 0 {
		return ErrUserDeleteFailed
	}

	var users []*User
	for _, p := range c.Users {
		if p.ID == id {
			continue
		}
		users = append(users, p)
	}
	c.Users = users
	return c.save()
}

func (c *Config) UpdateUser(id string, fn func(*User) error) error {
	c.Lock()
	defer c.Unlock()
	p, err := c.findUser(id)
	if err != nil {
		return err
	}
	if err := fn(p); err != nil {
		return err
	}
	return c.save()
}

func (c *Config) AddUser(email string) (User, error) {
	if user, err := c.FindUserByEmail(email); err == nil {
		return user, nil
	}

	c.Lock()
	defer c.Unlock()

	id := RandomString(16)
	user := User{
		ID:      id,
		Email:   email,
		Created: time.Now(),
	}
	c.Users = append(c.Users, &user)
	return user, c.save()
}

func (c *Config) FindUserByEmail(email string) (User, error) {
	c.RLock()
	defer c.RUnlock()
	u, err := c.findUserByEmail(email)
	if err != nil {
		return User{}, err
	}
	user := *u
	user.Profiles = []Profile{}
	for _, p := range c.listProfilesByUser(user.ID) {
		user.Profiles = append(user.Profiles, *p)
	}
	return user, nil
}

func (c *Config) findUserByEmail(email string) (*User, error) {
	for _, u := range c.Users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, ErrUserNotFound
}

func (c *Config) FindUser(id string) (User, error) {
	c.RLock()
	defer c.RUnlock()
	u, err := c.findUser(id)
	if err != nil {
		return User{}, err
	}
	user := *u
	user.Profiles = []Profile{}
	for _, p := range c.listProfilesByUser(user.ID) {
		user.Profiles = append(user.Profiles, *p)
	}
	return *u, nil
}

func (c *Config) findUser(id string) (*User, error) {
	for _, u := range c.Users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, ErrUserNotFound
}

func (c *Config) ListUsers() (users []User) {
	c.RLock()
	defer c.RUnlock()
	for _, u := range c.listUsers() {
		user := *u
		user.Profiles = []Profile{}
		for _, p := range c.listProfilesByUser(user.ID) {
			user.Profiles = append(user.Profiles, *p)
		}
		users = append(users, user)
	}
	return
}

func (c *Config) listUsers() (users []*User) {
	users = append(users, c.Users...)
	sort.Slice(users, func(i, j int) bool { return users[i].Created.After(users[j].Created) })
	return
}

func (c *Config) save() error {
	b, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}
	return Overwrite(c.filename, b, 0644)
}
