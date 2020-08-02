package org.example;


import com.nimbusds.jwt.SignedJWT;


import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

@WebServlet(name = "LoginServlet", urlPatterns = {"login"}, loadOnStartup = 1)
public class LoginServlet extends HttpServlet {
    // static login service which test the hardcoded username & passwd
    public LoginService loginService = new StaticLoginService();
    public JwtAuthService jwtAuthService = new JwtAuthService();
    RSAPublicKey publicKey = null;
    RSAPrivateKey privateKey = null;

    @Override
    public void init() throws ServletException {
        super.init();
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        kpg.initialize(2048);

        KeyPair kp = kpg.genKeyPair();
        publicKey = (RSAPublicKey) kp.getPublic();
        privateKey = (RSAPrivateKey) kp.getPrivate();

        try {
            writePemFile(privateKey, "RSA PRIVATE KEY", "id_rsa");
            writePemFile(publicKey, "RSA PUBLIC KEY", "id_rsa.pub");
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String user = req.getParameter("user");
        String passwd = req.getParameter("passwd");
        String serializedJWT = null;
        serializedJWT = getJWTFromRequest(req);

        if (serializedJWT == null) {
            if (user == null || passwd == null) {
                resp.setStatus(400);
                resp.getWriter().print("user/passwd are provided, can not attempt auth");
            } else {
                boolean isAuthenticated = loginService.loginUser(user, passwd);
                if (isAuthenticated) {
                    SignedJWT signedJWT = null;
                    try {
                        signedJWT = jwtAuthService.generateJWT(user,new Date(new Date().getTime() + 60000),privateKey);
                    } catch (Exception e) {
                        resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    }
                    resp.setHeader("Token",signedJWT.serialize());
                    resp.getWriter().print("User :"+user+",  is authenticated " + isAuthenticated+" Auth Method: Jwt Token");
                } else {
                    resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    resp.getWriter().print("Unauthorized, can't log in");
                }
            }
        } else {
            System.out.println("Found Token in request Header, proceeding with Parsing and validation");
            boolean valid = jwtAuthService.parseAndValidateToken(serializedJWT,publicKey);
            if (valid) {
                resp.setStatus(HttpServletResponse.SC_OK);
                resp.getWriter().print("User has valid JWT Token, granting him access");
            } else {
                resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
            }

        }   
    }



    protected String getJWTFromRequest(HttpServletRequest req) {
        if (req.getHeader("Token") != null) {
            return req.getHeader("Token");
        } else {
            return null;
        }
    }

    private static void writePemFile(Key key, String description, String filename)
            throws FileNotFoundException, IOException {
        PemFile pemFile = new PemFile(key, description);
        pemFile.write(filename);
    }
}