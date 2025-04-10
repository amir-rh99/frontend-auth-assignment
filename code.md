## کدهای API

### types/index.ts

```typescript
// Type definitions for the application

// User roles
export type Role = 'admin' | 'user';

// User with password (for database)
export interface User {
  id: number;
  username: string;
  password: string;
  name: string;
  role: Role;
}

// User without password (for client-side and JWT payload)
export type SafeUser = Omit<User, 'password'>;

// Login request payload
export interface LoginRequest {
  username: string;
  password: string;
}

// Login response
export interface LoginResponse {
  user: SafeUser;
  message: string;
}

// Error response
export interface ErrorResponse {
  error: string;
}
```

### lib/db.ts

```typescript
// Mock database for users
import { User, SafeUser } from '@/types';

// Mock users data - in a real app, this would be in a database
const users: User[] = [
  { 
    id: 1, 
    username: 'admin', 
    password: 'admin123', 
    name: 'Admin User',
    role: 'admin'
  },
  { 
    id: 2, 
    username: 'user', 
    password: 'user123', 
    name: 'Regular User',
    role: 'user'
  }
];

/**
 * Find a user by username and password
 * @param username Username
 * @param password Password
 * @returns User object if found, undefined otherwise
 */
export function findUserByCredentials(username: string, password: string): User | undefined {
  return users.find(
    (user) => user.username === username && user.password === password
  );
}

/**
 * Get all users (without passwords)
 * @returns Array of users without passwords
 */
export function getAllUsers(): SafeUser[] {
  // Remove passwords for security
  return users.map(({ password, ...user }) => user);
}
```

### lib/auth.ts

```typescript
// Authentication utilities for JWT token management
import jwt from 'jsonwebtoken';
import { cookies } from 'next/headers';
import { User, SafeUser } from '@/types';

const JWT_SECRET = 'your-secret-key';

/**
 * Generate a JWT token for the user
 * @param user User object
 * @returns JWT token
 */
export function generateToken(user: User): string {
  // Remove password from token payload
  const { password, ...userWithoutPassword } = user;
  
  const token = jwt.sign(
    userWithoutPassword as SafeUser,
    JWT_SECRET,
    { expiresIn: '1d' }
  );
  
  return token;
}

/**
 * Verify the JWT token
 * @param token JWT token
 * @returns User data if token is valid, null otherwise
 */
export function verifyToken(token: string): SafeUser | null {
  try {
    return jwt.verify(token, JWT_SECRET) as SafeUser;
  } catch (error) {
    return null;
  }
}

/**
 * Set JWT token in HTTP-only cookie
 * @param token JWT token
 */
export async function setTokenCookie(token: string): Promise<void> {
  const cookieStore = await cookies();
  
  cookieStore.set('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 60 * 24, // 1 day
    path: '/'
  });
}

/**
 * Clear JWT token cookie
 */
export async function clearTokenCookie(): Promise<void> {
  const cookieStore = await cookies();
  
  cookieStore.set('token', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 0,
    path: '/'
  });
}

/**
 * Get JWT token from cookie
 * @returns Token string if exists, undefined otherwise
 */
export async function getTokenFromCookie(): Promise<string | undefined> {
  const cookieStore = await cookies();
  return cookieStore.get('token')?.value;
}
```

### app/api/auth/login/route.ts

```typescript
// Login API endpoint
import { NextRequest, NextResponse } from 'next/server';
import { findUserByCredentials } from '@/lib/db';
import { generateToken, setTokenCookie } from '@/lib/auth';
import { LoginRequest, LoginResponse, ErrorResponse } from '@/types';

export async function POST(request: NextRequest): Promise<NextResponse<LoginResponse | ErrorResponse>> {
  try {
    const { username, password }: LoginRequest = await request.json();
    
    // Validate input
    if (!username || !password) {
      return NextResponse.json(
        { error: 'Username and password are required' },
        { status: 400 }
      );
    }
    
    // Find user
    const user = findUserByCredentials(username, password);
    if (!user) {
      return NextResponse.json(
        { error: 'Invalid username or password' },
        { status: 401 }
      );
    }
    
    // Generate token
    const token = generateToken(user);
    
    // Set token in cookie
    await setTokenCookie(token);
    
    // Return success response
    return NextResponse.json({
      user: {
        id: user.id,
        username: user.username,
        name: user.name,
        role: user.role
      },
      message: 'Login successful',
    });
    
  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json(
      { error: 'Server error' },
      { status: 500 }
    );
  }
}
```

### app/api/auth/logout/route.ts

```typescript
// Logout API endpoint
import { NextResponse } from 'next/server';
import { clearTokenCookie } from '@/lib/auth';

interface LogoutResponse {
  message: string;
}

interface LogoutErrorResponse {
  error: string;
}

export async function POST(): Promise<NextResponse<LogoutResponse | LogoutErrorResponse>> {
  try {
    // Clear token cookie
    await clearTokenCookie();
    
    // Return success response
    return NextResponse.json({
      message: 'Logout successful',
    });
    
  } catch (error) {
    console.error('Logout error:', error);
    return NextResponse.json(
      { error: 'Server error' },
      { status: 500 }
    );
  }
}
```

### app/api/auth/me/route.ts

```typescript
// Get current user API endpoint
import { NextResponse } from 'next/server';
import { getTokenFromCookie, verifyToken } from '@/lib/auth';
import { SafeUser } from '@/types';

interface MeResponse {
  user: SafeUser;
}

interface MeErrorResponse {
  error: string;
}

export async function GET(): Promise<NextResponse<MeResponse | MeErrorResponse>> {
  try {
    // Get token from cookie
    const token = await getTokenFromCookie();
    
    if (!token) {
      return NextResponse.json(
        { error: 'Not authenticated' },
        { status: 401 }
      );
    }
    
    // Verify token
    const user = verifyToken(token);
    
    if (!user) {
      return NextResponse.json(
        { error: 'Invalid token' },
        { status: 401 }
      );
    }
    
    // Return user data
    return NextResponse.json({ user });
    
  } catch (error) {
    console.error('Get user error:', error);
    return NextResponse.json(
      { error: 'Server error' },
      { status: 500 }
    );
  }
}
```

### app/api/admin/users/route.ts

```typescript
// Get all users API endpoint (admin only)
import { NextResponse } from 'next/server';
import { getAllUsers } from '@/lib/db';
import { SafeUser } from '@/types';

interface UsersResponse {
  users: SafeUser[];
}

interface UsersErrorResponse {
  error: string;
}

export async function GET(): Promise<NextResponse<UsersResponse | UsersErrorResponse>> {
  try {
    // Get all users (this endpoint is protected by middleware for admin only)
    const users = getAllUsers();
    
    return NextResponse.json({ users });
    
  } catch (error) {
    console.error('Get users error:', error);
    return NextResponse.json(
      { error: 'Server error' },
      { status: 500 }
    );
  }
}
```
