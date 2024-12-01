# SOS Backend Project

## Description
This is the backend service for the **SOS Project**, a system designed to manage user accounts and provide functionality for storing and updating emergency contact information. It is built using **Node.js** with support for user authentication and authorization.

---

## Features
- **User Registration & Authentication**:
  - Secure registration and login functionality using hashed passwords and JWT tokens.
- **Emergency Contact Management**:
  - Store and update up to five emergency contacts per user.
- **Token-based Authentication**:
  - Access control for APIs using JWT tokens.
- **Logout Support**:
  - Revoke the refresh token during logout.

---

## API Endpoints

### User Management
1. **Register a User**
   - **Endpoint**: `POST /register`
   - **Description**: Allows a new user to register by providing their details.
   - **Request Body**:
     ```json
     {
         "firstName": "John",
         "lastName": "Doe",
         "email": "johndoe@example.com",
         "password": "password123",
         "contactNumber": 1234567890,
         "emergencyNumber1":"5646458698",
         "emergencyNumber2":"5646586984",
         "emergencyNumber3":"5646455984",
         "emergencyNumber4":"5646475639",
         "emergencyNumber5":"5646458698"
     }
     ```
   - **Response**:
     - `201 Created`: User successfully registered.
     - `400 Bad Request`: Missing or invalid input.

2. **Login**
   - **Endpoint**: `POST /login`
   - **Description**: Authenticates the user and generates an access token and refresh token.
   - **Request Body**:
     ```json
     {
         "email": "johndoe@example.com",
         "password": "password123"
     }
     ```
   - **Response**:
     - `200 OK`: Login successful, tokens provided.
     - `401 Unauthorized`: Invalid credentials.

3. **Logout**
   - **Endpoint**: `POST /logout`
   - **Description**: Logs the user out by invalidating the refresh token.
   - **Response**:
     - `200 OK`: User successfully logged out.

---

### Emergency Contacts
1. **Get Emergency Contacts**
   - **Endpoint**: `GET /sos`
   - **Description**: Retrieves the user's stored emergency contact numbers.
   - **Response**:
     - `200 OK`: Returns the user's emergency contacts.
     ```json
     {
         "emergencyNumber1": 1234567890,
         "emergencyNumber2": 9876543210,
         "emergencyNumber3": 1122334455,
         "emergencyNumber4": 5566778899,
         "emergencyNumber5": 2233445566
     }
     ```
     - `404 Not Found`: User not found.

2. **Update Emergency Contacts**
   - **Endpoint**: `GET /updatecontact`
   - **Description**: Allows the user to update their emergency contacts.
   - **Request Body** (Optional fields):
     ```json
     {
         "emergencyNumber1": 1234567890,
         "emergencyNumber2": 9876543210,
         "emergencyNumber3": 1122334455,
         "emergencyNumber4": 5566778899,
         "emergencyNumber5": 2233445566
     }
     ```
   - **Response**:
     - `200 OK`: Emergency contacts updated successfully.
     - `400 Bad Request`: Invalid data provided.

---

## Technologies Used
- **Node.js**: Backend runtime environment.
- **Express.js**: Web framework for building REST APIs.
- **MongoDB**: Database for storing user and emergency contact details.
- **JWT**: Token-based authentication.
- **bcrypt**: Password hashing for secure authentication.

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Wajidalihashmi29/SOS_Project.git
2. Install dependencies
   ```
   npm install
3. Configure environment variables:

  - Edit.env file and set the following variables
    ```bash
    PORT=3000
    MONGO_URI=<your-mongodb-uri>
    ACCESS_TOKEN_SECRET=<your-access-token-secret>
    REFRESH_TOKEN_SECRET=<your-refresh-token-secret>
    ACCESS_TOKEN_EXPIRY=15m
    REFRESH_TOKEN_EXPIRY=7d
4. Start the server:
  ```
  npm run dev
```
## Testing the APIs
Use Postman or any API client to test the endpoints. For secured endpoints, include the Authorization header with the Bearer token.

    

