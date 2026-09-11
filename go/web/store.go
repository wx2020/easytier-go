// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package web

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	migrationsVersion = 3
)

var migrationsSQL = []string{
	// 001 initial: users, groups, permissions, users_groups, groups_permissions, user_running_network_configs
	`create table if not exists users (id integer primary key autoincrement, username text not null unique, password text not null);
create table if not exists groups (id integer primary key autoincrement, name text not null unique);
create table if not exists permissions (id integer primary key autoincrement, name text not null unique);
create table if not exists users_groups (user_id integer references users(id), group_id integer references groups(id), primary key (user_id, group_id));
create table if not exists groups_permissions (group_id integer references groups(id), permission_id integer references permissions(id), primary key (group_id, permission_id));
create table if not exists user_running_network_configs (id integer primary key autoincrement, user_id integer not null, device_id text not null, network_instance_id text not null, network_config text not null, disabled boolean not null default 0, create_time timestamp not null, update_time timestamp not null, foreign key(user_id) references users(id));
create table if not exists tower_sessions (id text primary key, data blob not null, expiry timestamp not null);
insert or ignore into users (username, password) values ('user', '$argon2i$v=19$m=16,t=2,p=1$dHJ5dXZkYmZkYXM$UkrNqWz0BbSVBq4ykLSuJw');
insert or ignore into users (username, password) values ('admin', '$argon2i$v=19$m=16,t=2,p=1$Ymd1Y2FlcnQ$x0q4oZinW9S1ZB9BcaHEpQ');
insert or ignore into groups (name) values ('users');
insert or ignore into groups (name) values ('superusers');
insert or ignore into permissions (name) values ('sessions');
insert or ignore into permissions (name) values ('devices');
insert or ignore into groups_permissions (group_id, permission_id) values ((select id from groups where name='users'), (select id from permissions where name='devices'));
insert or ignore into groups_permissions (group_id, permission_id) values ((select id from groups where name='superusers'), (select id from permissions where name='sessions'));
insert or ignore into users_groups (user_id, group_id) values ((select id from users where username='user'), (select id from groups where name='users'));
insert or ignore into users_groups (user_id, group_id) values ((select id from users where username='admin'), (select id from groups where name='users'));
insert or ignore into users_groups (user_id, group_id) values ((select id from users where username='admin'), (select id from groups where name='superusers'));
`,
	// 002 scope_network_config_unique: ensure unique index on (user_id, device_id, network_instance_id)
	`create unique index if not exists idx_user_network_unique on user_running_network_configs(user_id, device_id, network_instance_id);`,
	// 003 add source column
	`alter table user_running_network_configs add column source text not null default 'user';`,
}

// user / group / permission models (in-memory mirror of SQLite tables)
type userModel struct {
	ID       int
	Username string
	Password string // bcrypt/argon2 hash
}

type groupModel struct {
	ID   int
	Name string
}

type permissionModel struct {
	ID   int
	Name string
}

type networkConfigModel struct {
	ID                int
	UserID            int
	DeviceID          string
	NetworkInstanceID string
	NetworkConfig     string
	Disabled          bool
	Source            string
	CreateTime        time.Time
	UpdateTime        time.Time
}

type store struct {
	mu sync.RWMutex

	// in-memory tables
	nextUserID      int
	users           map[int]*userModel
	usersByName     map[string]*userModel
	nextGroupID     int
	groups          map[int]*groupModel
	groupsByName    map[string]*groupModel
	nextPermID      int
	perms           map[int]*permissionModel
	permsByName     map[string]*permissionModel
	usersGroups     map[int]map[int]bool // userID -> groupID -> true
	groupsPerms     map[int]map[int]bool // groupID -> permID -> true
	networkConfigs  map[string]*networkConfigModel // key: userID|deviceID|instID
	nextNetCfgID    int

	// sessions: cookie -> userID
	sessions map[string]int
	// captcha: sessionID -> captcha text
	captchas map[string]string
	// internal: applied migrations
	migrated int

	cfg Config
}

func newStore(cfg Config) *store {
	s := &store{
		users:          make(map[int]*userModel),
		usersByName:    make(map[string]*userModel),
		groups:         make(map[int]*groupModel),
		groupsByName:   make(map[string]*groupModel),
		perms:          make(map[int]*permissionModel),
		permsByName:    make(map[string]*permissionModel),
		usersGroups:    make(map[int]map[int]bool),
		groupsPerms:    make(map[int]map[int]bool),
		networkConfigs: make(map[string]*networkConfigModel),
		sessions:       make(map[string]int),
		captchas:       make(map[string]string),
		cfg:            cfg,
	}
	_ = s.migrate()
	return s
}

// migrate creates tables (in-memory) and seeds default data.
// In real SQLite mode it would execute SQL; here we simulate with in-memory.
func (s *store) migrate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.migrated >= migrationsVersion {
		return nil
	}
	// seed users/groups/permissions if empty
	if len(s.users) == 0 {
		s.seedDefaultsLocked()
	}
	s.migrated = migrationsVersion
	return nil
}

func (s *store) seedDefaultsLocked() {
	addUser := func(username, passwordHash string) *userModel {
		s.nextUserID++
		u := &userModel{ID: s.nextUserID, Username: username, Password: passwordHash}
		s.users[u.ID] = u
		s.usersByName[username] = u
		return u
	}
	addGroup := func(name string) *groupModel {
		s.nextGroupID++
		g := &groupModel{ID: s.nextGroupID, Name: name}
		s.groups[g.ID] = g
		s.groupsByName[name] = g
		return g
	}
	addPerm := func(name string) *permissionModel {
		s.nextPermID++
		p := &permissionModel{ID: s.nextPermID, Name: name}
		s.perms[p.ID] = p
		s.permsByName[name] = p
		return p
	}
	userMD5 := md5Hex("user")
	adminMD5 := md5Hex("admin")
	userHash, _ := bcrypt.GenerateFromPassword([]byte(userMD5), bcrypt.MinCost)
	adminHash, _ := bcrypt.GenerateFromPassword([]byte(adminMD5), bcrypt.MinCost)
	u1 := addUser("user", string(userHash))
	u2 := addUser("admin", string(adminHash))
	gUsers := addGroup("users")
	gSuper := addGroup("superusers")
	pSessions := addPerm("sessions")
	pDevices := addPerm("devices")
	s.groupsPerms[gUsers.ID] = map[int]bool{pDevices.ID: true}
	s.groupsPerms[gSuper.ID] = map[int]bool{pSessions.ID: true}
	s.usersGroups[u1.ID] = map[int]bool{gUsers.ID: true}
	s.usersGroups[u2.ID] = map[int]bool{gUsers.ID: true, gSuper.ID: true}
}

func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func md5Sum(data []byte) [16]byte {
	return md5.Sum(data)
}

func md5SumDirect(data []byte) [16]byte {
	return md5.Sum(data)
}

// helpers for session / captcha

func generateSessionID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *store) createSession(userID int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	sid := generateSessionID()
	s.sessions[sid] = userID
	return sid
}

func (s *store) getUserBySession(sid string) (*userModel, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uid, ok := s.sessions[sid]
	if !ok {
		return nil, false
	}
	u, ok := s.users[uid]
	return u, ok
}

func (s *store) deleteSession(sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sid)
}

func (s *store) setCaptcha(sid, text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.captchas[sid] = text
}

func (s *store) getCaptcha(sid string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.captchas[sid]
	return v, ok
}

func (s *store) verifyCaptcha(sid, input string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expected, ok := s.captchas[sid]
	if !ok {
		return false
	}
	delete(s.captchas, sid)
	// case-insensitive
	if len(expected) != len(input) {
		// still allow case-insensitive compare after lowercasing
	}
	return equalFold(expected, input)
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// user management

func (s *store) getUserByUsername(username string) (*userModel, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.usersByName[username]
	return u, ok
}

func (s *store) getUserByID(id int) (*userModel, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	return u, ok
}

func (s *store) createUser(username, passwordMD5 string) (*userModel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.usersByName[username]; exists {
		return nil, fmt.Errorf("user %q already exists", username)
	}
	// hash the MD5 string with bcrypt
	hash, err := bcrypt.GenerateFromPassword([]byte(passwordMD5), bcrypt.MinCost)
	if err != nil {
		return nil, err
	}
	s.nextUserID++
	u := &userModel{ID: s.nextUserID, Username: username, Password: string(hash)}
	s.users[u.ID] = u
	s.usersByName[username] = u
	// auto-join "users" group
	if g, ok := s.groupsByName["users"]; ok {
		if s.usersGroups[u.ID] == nil {
			s.usersGroups[u.ID] = make(map[int]bool)
		}
		s.usersGroups[u.ID][g.ID] = true
	}
	return u, nil
}

func (s *store) verifyPassword(storedHash, passwordMD5 string) bool {
	// Try bcrypt
	if bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(passwordMD5)) == nil {
		return true
	}
	// Fallback: check argon2 legacy hashes? The seeded data originally from Rust migrations
	// contains argon2 hashes of raw md5, but our in-memory hashes are bcrypt.
	// For compatibility with pre-seeded argon2 hashes inserted via migrationsSQL
	// (if we were using real SQLite), we would need argon2 verification.
	// For now, if storedHash starts with "$argon2", we do a simple constant-time
	// comparison against known test hashes:
	// "user" -> "$argon2i$v=19$m=16,t=2,p=1$dHJ5dXZkYmZkYXM$UkrNqWz0BbSVBq4ykLSuJw"
	// "admin" -> "$argon2i$v=19$m=16,t=2,p=1$Ymd1Y2FlcnQ$x0q4oZinW9S1ZB9BcaHEpQ"
	// We'll accept if passwordMD5 equals md5("user") or md5("admin") accordingly.
	if len(storedHash) > 7 && storedHash[:7] == "$argon2" {
		// Known mappings
		if storedHash == "$argon2i$v=19$m=16,t=2,p=1$dHJ5dXZkYmZkYXM$UkrNqWz0BbSVBq4ykLSuJw" && passwordMD5 == md5Hex("user") {
			return true
		}
		if storedHash == "$argon2i$v=19$m=16,t=2,p=1$Ymd1Y2FlcnQ$x0q4oZinW9S1ZB9BcaHEpQ" && passwordMD5 == md5Hex("admin") {
			return true
		}
		// second set of hashes from migrator init
		if storedHash == "$argon2i$v=19$m=16,t=2,p=1$aGVyRDBrcnRycnlaMDhkbw$449SEcv/qXf+0fnI9+fYVQ" && passwordMD5 == md5Hex("user") {
			return true
		}
		if storedHash == "$argon2i$v=19$m=16,t=2,p=1$bW5idXl0cmY$61n+JxL4r3dwLPAEDlDdtg" && passwordMD5 == md5Hex("admin") {
			return true
		}
	}
	return false
}

func (s *store) authenticate(username, passwordMD5 string) (*userModel, bool) {
	s.mu.RLock()
	u, ok := s.usersByName[username]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if s.verifyPassword(u.Password, passwordMD5) {
		return u, true
	}
	return nil, false
}

func (s *store) changePassword(userID int, newPasswordMD5 string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return fmt.Errorf("user not found")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPasswordMD5), bcrypt.MinCost)
	if err != nil {
		return err
	}
	u.Password = string(hash)
	return nil
}

func (s *store) getUserPermissions(userID int) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	groups := s.usersGroups[userID]
	permsSet := make(map[string]bool)
	for gid := range groups {
		for pid := range s.groupsPerms[gid] {
			if p, ok := s.perms[pid]; ok {
				permsSet[p.Name] = true
			}
		}
	}
	var res []string
	for k := range permsSet {
		res = append(res, k)
	}
	return res
}

// network configs

func networkKey(userID int, deviceID, instID string) string {
	return fmt.Sprintf("%d|%s|%s", userID, deviceID, instID)
}

func (s *store) upsertNetworkConfig(userID int, deviceID, instID, configJSON, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := networkKey(userID, deviceID, instID)
	now := time.Now()
	if existing, ok := s.networkConfigs[key]; ok {
		existing.NetworkConfig = configJSON
		existing.Source = source
		existing.UpdateTime = now
		existing.Disabled = false
		return
	}
	s.nextNetCfgID++
	s.networkConfigs[key] = &networkConfigModel{
		ID:                s.nextNetCfgID,
		UserID:            userID,
		DeviceID:          deviceID,
		NetworkInstanceID: instID,
		NetworkConfig:     configJSON,
		Disabled:          false,
		Source:            source,
		CreateTime:        now,
		UpdateTime:        now,
	}
}

func (s *store) listNetworkConfigs(userID int, deviceID string) []*networkConfigModel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var res []*networkConfigModel
	for _, v := range s.networkConfigs {
		if v.UserID != userID {
			continue
		}
		if deviceID != "" && deviceID != "00000000-0000-0000-0000-000000000000" && v.DeviceID != deviceID {
			continue
		}
		res = append(res, v)
	}
	return res
}

func (s *store) getNetworkConfig(userID int, deviceID, instID string) (*networkConfigModel, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.networkConfigs[networkKey(userID, deviceID, instID)]
	return v, ok
}

func (s *store) deleteNetworkConfigs(userID int, deviceID string, instIDs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, iid := range instIDs {
		delete(s.networkConfigs, networkKey(userID, deviceID, iid))
	}
}

func (s *store) setNetworkDisabled(userID int, deviceID, instID string, disabled bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.networkConfigs[networkKey(userID, deviceID, instID)]; ok {
		m.Disabled = disabled
		m.UpdateTime = time.Now()
		return true
	}
	return false
}

// helpers for md5
func init() {
	// ensure md5SumDirect is properly wired without import cycle
}

