#API AUTH WITH KEYCLOAK

**Startup keycloak**
```
docker compose up -d
```
**Admin keycloak**
http://localhost:8081

***user and password admin/admin***

Create realm and client with name authdemo
copy client credentials

**Start api-auth-with-keycloak**
```
cd api-auth-with-keycloak
./gradlew bootRun
```

**Login page keycloak**
http://localhost:8080/oauth2/authorization/keycloak
