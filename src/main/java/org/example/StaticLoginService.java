package org.example;

// static login service having hardcoded user/passwd.
public class StaticLoginService implements LoginService {
    private LoginInfo loginInfo;

    public StaticLoginService() {
        this.loginInfo = new LoginInfo("raj@example.org","testpass");
    }

    public boolean loginUser(String user, String pass) {
        return loginInfo.username.equals(user) && loginInfo.password.equals(pass);
    }

    private class LoginInfo {
        String username;
        String password;

        LoginInfo(String username,String password) {
            this.username = username;
            this.password = password;
        }
    }
}
