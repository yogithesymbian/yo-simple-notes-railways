DEMO : https://yo-simple-notes-railways-production.up.railway.app/{endpoint}

```
git clone https://github.com/yogithesymbian/yo-simple-notes-railways.git
go get github.com/golang-jwt/jwt/v5
go get github.com/gorilla/mux
go get github.com/joho/godotenv
go get github.com/go-sql-driver/mysql
go get golang.org/x/crypto/bcrypt
go run main.go
```

# 📘 Notes API with JWT - Documentation

Base URL: `http://localhost:8080`

---

## 🔐 Authentication

### POST `/login`

Login dan dapatkan JWT token.

**Request Body**

```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response**

```json
{
  "token": "JWT_TOKEN_HERE"
}
```

> Gunakan token ini di header untuk semua endpoint `/notes`:

```
Authorization: JWT_TOKEN_HERE
```

---

## 📒 Notes Endpoints (Protected)

### GET `/notes`

Mengambil semua catatan.

**Headers**

```
Authorization: JWT_TOKEN_HERE
```

**Response**

```json
[
  {
    "id": 1,
    "title": "Judul Catatan",
    "content": "Isi catatan"
  }
]
```

---

### GET `/notes/{id}`

Ambil detail catatan berdasarkan ID.

**Headers**

```
Authorization: JWT_TOKEN_HERE
```

**Response**

```json
{
  "id": 1,
  "title": "Judul Catatan",
  "content": "Isi catatan"
}
```

---

### POST `/notes`

Membuat catatan baru.

**Headers**

```
Authorization: JWT_TOKEN_HERE
Content-Type: application/json
```

**Request Body**

```json
{
  "title": "Catatan Baru",
  "content": "Isi dari catatan baru"
}
```

**Response**

```json
{
  "id": 2,
  "title": "Catatan Baru",
  "content": "Isi dari catatan baru"
}
```

---

### PUT `/notes/{id}`

Update catatan berdasarkan ID.

**Headers**

```
Authorization: JWT_TOKEN_HERE
Content-Type: application/json
```

**Request Body**

```json
{
  "title": "Judul Update",
  "content": "Isi yang sudah diperbarui",
  "mark_done": true
}
```

**Response**

```json
{
  "id": 2,
  "title": "Judul Update",
  "content": "Isi yang sudah diperbarui",
  "mark_done": true
}
```

---

### DELETE `/notes/{id}`

Hapus catatan berdasarkan ID.

**Headers**

```
Authorization: JWT_TOKEN_HERE
```

**Response**

```
204 No Content
```

---

## 📝 Tambahan

### ✅ Test User

Pastikan user `admin` ada dalam tabel `users`:

```sql
INSERT INTO users (username, password) VALUES ('admin', 'admin123');
```

### ⚠️ Catatan Keamanan

- Password belum di-hash (gunakan bcrypt untuk real project)
- Jangan expose token lewat query string
- Tambahkan rate-limit / logging di production

---

```

```
