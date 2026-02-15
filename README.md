# Contera Server

## Overview
Contera Server is the backend API for the Contera contest platform. It handles authentication (JWT), role-based access (user/creator/admin), contest management, contest registration via Stripe payments, task submissions, winner declaration, and leaderboard generation.

---

## Purpose
This server provides a secure and scalable REST API to:
- Serve public contest data (approved/confirmed contests)
- Allow creators to create contests and manage submissions
- Allow admins to manage users and approve/reject contests
- Process contest entry payments using Stripe
- Track registrations, submissions, winners, and leaderboard stats


## Key Features
- **JWT Authentication**
  - Issues JWT tokens and protects private routes using `Authorization: Bearer <token>` header.

- **Role-Based Access Control**
  - **Admin:** manage users, approve/reject contests, remove contests.
  - **Creator:** create contests, view submissions, declare winners.
  - **User:** register (pay), submit tasks, view participated/winning contests.

- **Contest System**
  - Public endpoints return only `confirmed` contests.
  - Contest search/filtering by contest type.

- **Stripe Payment Flow**
  - Creates Stripe checkout session
  - Confirms payment and registers user
  - Prevents duplicate participant count increments

- **Participation Rules**
  - Admin cannot participate in any contest
  - Creator can participate in contests except their own
  - Contest must be confirmed and not ended before allowing participation

- **Submissions & Winner Declaration**
  - Only registered (paid) users can submit
  - Creator can declare exactly one winner after deadline
  - Winner updates contest + submissions and increments `winsCount`

- **Leaderboard**
  - Returns ranked users by `winsCount` (supports both user + creator, excludes admin)

- **Basic Site Stats**
  - Totals for contests, winners, participants, and prize money

---

## Tech Stack
- **Node.js**
- **Express.js**
- **MongoDB Atlas**
- **JWT (jsonwebtoken)**
- **Stripe**
- **CORS**
- **dotenv**
- **Vercel (deployment)**

---

## NPM Packages Used
- `express` — web server framework
- `cors` — cross-origin request handling
- `dotenv` — environment variable management
- `mongodb` — MongoDB client for database operations
- `jsonwebtoken` — JWT generation and verification
- `stripe` — Stripe checkout session and payment verification