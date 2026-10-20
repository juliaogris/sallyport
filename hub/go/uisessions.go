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
	m  map[string]uiSession
}

// uiSession is the web session sid of user, and the time of the launch it
// is held for.
type uiSession struct {
	user, sid string
	launched  time.Time
}

// put holds the web session webSID of user for the app session appSID,
// launched at now.
func (u *uiSessions) put(appSID, user, webSID string, now time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.purge(now)
	if u.m == nil {
		u.m = make(map[string]uiSession)
	}
	u.m[appSID] = uiSession{user: user, sid: webSID, launched: now}
}

// take returns and deletes the session held for the app session appSID.
// It returns false if there is none, or if its launch was more than
// uiSessionTTL before now.
func (u *uiSessions) take(appSID string, now time.Time) (uiSession, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.purge(now)
	s, ok := u.m[appSID]
	delete(u.m, appSID)
	return s, ok
}

// purge deletes the entries whose launch was more than uiSessionTTL before
// now. u.mu must be held.
func (u *uiSessions) purge(now time.Time) {
	for id, s := range u.m {
		if now.Sub(s.launched) > uiSessionTTL {
			delete(u.m, id)
		}
	}
}
