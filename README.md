# Аутентификации JWT с помощью Spring Boot

 Это простое приложение Spring Boot, которое демонстрирует, как реализовать аутентификацию JWT (JSON Web Token) для защиты RESTful API. Он предоставляет конечные точки для регистрации пользователей, аутентификации пользователей.

## Функции
- Регистрация пользователя: позволяет пользователям регистрироваться, указав имя пользователя, пароль и электронную почту.
- Аутентификация пользователя: проверяет учетные данные пользователя и генерирует токен JWT для последующих запросов API.
- Аутентификация на основе токенов JWT: защищает конечные точки API с помощью токенов JWT.
- Получение сведений о пользователе: предоставляет конечную точку для получения сведений о пользователе на основе маркера JWT, прошедшего проверку подлинности.

## Использованные технологии

- Java 17+
- Spring Boot
- Spring Security
- Spring Data JPA
- Mongo Database
- JWT (JSON Web Tokens)

## Конфигурация 
- Секретный ключ JWT и срок действия токена можно настроить в файле.application.yml
- В демонстрационных целях используется база данных Mongo database. Вы можете переключиться на другую базу данных, настроив файл соответствующим образом.application.yml

## Безопасность

- Пароли хешируются с помощью алгоритма хеширования BCrypt перед их сохранением в базе данных.
- Конечные точки защищены с помощью токенов Spring Security и JWT.
- Токены JWT проверяются перед предоставлением доступа к защищенным конечным точкам.