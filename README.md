# 🔐 Incognote

Bezpieczna aplikacja do współdzielonych notatek z szyfrowaniem i kontrolą dostępu.

---

## Architektura

* **Backend:** Rust (Axum)
* **DB:** PostgreSQL (sqlx)
* **Frontend:** HTML + HTMX / vanilla JS
* **Infra:** Docker Compose

### Mikroserwisy:

* **Auth Service (3001)** – logowanie, JWT, role
* **Notes Service (3002)** – notatki, szyfrowanie, uprawnienia

---

## Baza danych

3 tabele:

* `users`
* `notes`
* `note_permissions`

---

## Funkcje

### Auth Service

* rejestracja / logowanie
* JWT auth
* role: `admin`, `user`
* basic brute-force protection

### Notes Service

* CRUD notatek
* udostępnianie: `read / write`
* opcjonalne szyfrowanie AES-256-GCM
* kontrola dostępu (RBAC)
* audit log dostępu

---

## Security focus

System został zaprojektowany z naciskiem na:

* brak IDOR (sprawdzanie ownership + permissions)
* ochrona przed SQL injection (parametryzacja)
* XSS (sanityzacja treści)
* brute-force protection (login throttling)
* JWT-based auth
* fail-secure behavior

---

## Failure scenarios

* Auth Service down → brak logowania (deny by default)
* Notes Service down → brak dostępu do notatek, auth działa dalej

---

## External API

Używane API:

* IP geolocation (logowanie kraju użytkownika)

---

## Uruchomienie

```bash
docker-compose up --build
```

* Frontend: [http://localhost:8080](http://localhost:8080)
* Auth: [http://localhost:3001/health](http://localhost:3001/health)
* Notes: [http://localhost:3002/health](http://localhost:3002/health)
