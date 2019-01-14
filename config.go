package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

var (
	ErrProfileNotFound = errors.New("profile not found")
)

type Profile struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Platform string    `json:"platform"`
	Number   int       `json:"number"`
	Created  time.Time `json:"created"`
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
	Mail       struct {
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
		return c, c.save()
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

func (c *Config) AddProfile(name, platform string) (Profile, error) {
	c.Lock()
	defer c.Unlock()

	var id string
	for {
		n := RandomString(16)
		if _, err := c.findProfile(n); err == ErrProfileNotFound {
			id = n
			break
		}
	}
	number := 2 // MUST start at 2
	for _, p := range c.Profiles {
		if p.Number >= number {
			number = p.Number + 1
		}
	}
	profile := Profile{
		ID:       id,
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

func (c *Config) ListProfiles() (profiles []Profile) {
	c.RLock()
	defer c.RUnlock()
	for _, p := range c.listProfiles() {
		profiles = append(profiles, *p)
	}
	return
}

func (c *Config) listProfiles() (profiles []*Profile) {
	for _, p := range c.Profiles {
		profiles = append(profiles, p)
	}
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

func (c *Config) save() error {
	b, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}
	return Overwrite(c.filename, b, 0644)
}
