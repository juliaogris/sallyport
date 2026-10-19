package main

import (
	"sync"
	"time"
)

// uiSessionTTL is how long after a launch the handoff can still take the
// launch's web session.
const uiSessionTTL = 60 * time.Second

// uiSessions holds the web session that each launch of an app in
// WEB_UI_APPS was made with, by app session ID, so that the handoff on the
// app host can log the app's web UI in with it. Each entry is taken once,
// and only within uiSessionTTL of its launch. The entries are in memory,
// so a restart between a launch and its handoff loses them, and the UI
// then asks for its own login.
type uiSessions struct {
	mu sync.Mutex
	// now is time.Now, or a fake clock in tests.
	now func() time.Time
	m   map[string]uiSession
}

// uiSession is the web session sid of user, and the time of the launch it
// is held for.
type uiSession struct {
	user, sid string
	launched  time.Time
}

// put holds s for the app session appSID.
func (u *uiSessions) put(appSID string, s uiSession) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.purge()
	if u.m == nil {
		u.m = make(map[string]uiSession)
	}
	s.launched = u.clock()
	u.m[appSID] = s
}

// take returns and deletes the session held for the app session appSID.
// It returns false if there is none, or if its launch was more than
// uiSessionTTL ago.
func (u *uiSessions) take(appSID string) (uiSession, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.purge()
	s, ok := u.m[appSID]
	delete(u.m, appSID)
	return s, ok
}

// purge deletes the entries whose launch was more than uiSessionTTL ago.
// u.mu must be held.
func (u *uiSessions) purge() {
	now := u.clock()
	for id, s := range u.m {
		if now.Sub(s.launched) > uiSessionTTL {
			delete(u.m, id)
		}
	}
}

func (u *uiSessions) clock() time.Time {
	if u.now != nil {
		return u.now()
	}
	return time.Now()
}
