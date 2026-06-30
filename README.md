# ⌨️ Typing Master — MongoDB Backend

## Quick Start

```bash
npm install
npm start
```

Server: http://localhost:3000

## MongoDB
Connection string already set hai server.js mein.
Change karna ho toh `MONGO_URI` env variable set karo:
```bash
MONGO_URI="your_uri_here" npm start
```

## Default Admin Login
- Email:    admin@typing.com
- Password: admin123

## Features
- ✅ Register / Login / Logout (session MongoDB mein store hoti hai)
- ✅ 10 Levels Typing Test
- ✅ Live WPM + Accuracy
- ✅ Result MongoDB mein save
- ✅ Profile page (naam, bio edit + password change)
- ✅ Test History (last 50 tests)
- ✅ Leaderboard (Aggregation pipeline — Best WPM per user)
- ✅ Admin Dashboard (stats, charts, user management)
- ✅ Admin: Delete user, Reset results, Toggle admin

## MongoDB Collections
- `users`    — registered users
- `results`  — typing test results
- `sessions` — login sessions (connect-mongo)

## File Structure
```
typing_master/
├── server.js           ← Express + Mongoose backend
├── package.json
├── data/
│   └── paragraphs.js
└── public/
    ├── index.html       ← Login/Register
    ├── typing.html      ← Typing test
    ├── profile.html     ← User profile
    ├── leaderboard.html ← Top typers
    └── admin.html       ← Admin panel
```
