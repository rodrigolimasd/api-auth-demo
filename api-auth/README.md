#Api-Auth-Demo

Spring Boot 3, Spring Autho2 Authorization Server

------
**Request Client Credentials**
```
curl --location 'http://localhost:9000/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=' \
--data-urlencode 'scope=message.read message.write' \
--data-urlencode 'grant_type=client_credentials'
```

