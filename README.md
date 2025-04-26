# User Authentication Service

A Node.js/Express.js service for handling user authentication with JWT tokens. This service provides endpoints for user registration, login, token validation, and token refresh.

## Features

- User registration and login
- JWT-based authentication
- Token validation and refresh
- Secure password hashing with bcrypt
- MongoDB integration for user storage

## Installation

1. Clone the repository:
```
git clone https://github.com/AjinkyaSambare/user-authentication-service.git
cd user-authentication-service
```

2. Install dependencies:
```
npm install
```

3. Create a `.env` file in the root directory with the following variables:
```
PORT=3000
MONGODB_URI=mongodb://localhost:27017/auth-service
JWT_SECRET=your_jwt_secret_key
JWT_EXPIRY=24h
```

4. Start the server:
```
npm start
```

For development with auto-restart:
```
npm run dev
```

## API Endpoints

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login a user and receive tokens
- `POST /api/auth/refresh` - Refresh an authentication token
- `POST /api/auth/logout` - Logout a user and invalidate tokens
- `GET /api/auth/validate` - Validate a token

## Testing

Run the test suite with:
```
npm test
```

## Known Issues

- **Issue #42**: Authentication tokens don't expire after the specified timeout.
  - Tokens created with a 24-hour expiration are still valid after that period.
  - This is a security issue that needs to be addressed.

## License

MIT
