# To-Do List API

A simple RESTful API for managing personal to-do lists with user authentication and CRUD functionality.

## Hosted API
- **URL**: [https://brayden-todo-151e08866201.herokuapp.com/](https://brayden-todo-151e08866201.herokuapp.com/)

## Endpoints

### 1. **User Registration**
   - **POST** `/register`
   - **Body**: `{ "name": "John", "email": "john@doe.com", "password": "password" }`
   - **Response**: `{ "token": "<JWT_TOKEN>" }`

### 2. **User Login**
   - **POST** `/login`
   - **Body**: `{ "email": "john@doe.com", "password": "password" }`
   - **Response**: `{ "token": "<JWT_TOKEN>" }`

### 3. **Create To-Do Item**
   - **POST** `/todos`
   - **Headers**: `Authorization: <token>`
   - **Body**: `{ "title": "Buy groceries", "description": "Buy milk" }`
   - **Response**: `{ "id": 1, "title": "Buy groceries", "description": "Buy milk" }`

### 4. **Update To-Do Item**
   - **PUT** `/todos/:id`
   - **Headers**: `Authorization: <token>`
   - **Body**: `{ "title": "New Title", "description": "New Description" }`
   - **Response**: `{ "id": 1, "title": "New Title", "description": "New Description" }`

### 5. **Delete To-Do Item**
   - **DELETE** `/todos/:id`
   - **Headers**: `Authorization: <token>`
   - **Response**: Status `204 No Content`

### 6. **Get To-Do Items**
   - **GET** `/todos?page=1&limit=10`
   - **Headers**: `Authorization: <token>`
   - **Response**:
     ```json
     {
       "data": [{ "id": 1, "title": "Task", "description": "Description" }],
       "page": 1,
       "limit": 10,
       "total": 1
     }
     ```

## Local Setup
1. Clone repo, install dependencies: `npm install`
2. Set up `.env` with `JWT_SECRET` and `MONGO_URI`
3. Run locally: `npm start`
