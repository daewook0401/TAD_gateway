# TAD Gateway

TAD 인증 API와 Gateway 경계를 담당하기 위한 Spring Boot 서비스입니다.

## Local Database

- PostgreSQL: `localhost:5001`
- Database: `test_tad_db`
- Schema: `auth`
- User: `tad_app`
- Redis: `localhost:6001`

`application*.yml` files are intentionally ignored. Keep local DB, Redis, mail, and JWT values in an untracked YAML file or pass them as runtime properties.

Refresh tokens are issued as an HttpOnly cookie by Gateway auth endpoints. For cross-origin local frontend calls, the frontend must send auth requests with credentials enabled.

운영 전환 시에는 같은 스키마 구조를 유지하고 DB명을 `tad_db`로 전환하는 방향을 기준으로 합니다.
