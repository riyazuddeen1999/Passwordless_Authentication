# WebAuthn Auth System (minimal)

## Requirements
- Node.js (v18+ recommended)
- MongoDB running locally on default port (mongodb://127.0.0.1:27017)

## Setup
1. unzip the project
2. cd into the folder
3. npm install
4. start MongoDB (e.g., `brew services start mongodb-community` on macOS)
5. npm start
6. Open http://localhost:3001 in your browser (use Chrome or Safari on macOS)

## Notes
- This demo uses platform authenticators (Touch ID) by default.
- For local testing use `localhost` origin.
