# JWTAuthService
A Jetty based auth service demonstrating the JWT Token Authentication framework.
The way it currently work is, user sent the request, if rquest does not contains the token
then it try to authenticate the user, for sake of simplicity I am using the StaticLoginService
which has username and password hardcoded for authentication purpose but feel free to implement
LoginService of your choice (e.g. DBservice, external service) to check the validate authentication.


once user is validated, JWTAuthService generate the Token which is pushed to the user through
response header, the same can be used for susequent requests.

#### How to Build and Run
```
./gradlew apprun

15:41:19 INFO  Jetty 9.2.26.v20180806 started and listening on port 8080
15:41:19 INFO   runs at:
15:41:19 INFO    http://localhost:8080/

> Task :appRun
Press any key to stop the server.
```

#### How to Test
Please use following Java 11 Http Client to test the application

https://gist.github.com/rajkrrsingh/9a8a93c1be32034d8eda4be2fca1d036

The Client sends the 2 HttpRequest, first request has no token but username and password, The service trigger the
auth based on the supplied credential and send the token, next request send the token to the service which was validated
at server.