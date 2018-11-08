package com.soauth.server.service.business;

import com.soauth.core.vo.oauth2.RefreshToken;
import org.jose4j.jwt.JwtClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * @author zhoujie
 * @date 2017/12/5
 */
@Service
public class AuthRefreshToken {

    private static Logger logger = LoggerFactory.getLogger(AuthRefreshToken.class);

    public JwtClaims createRefreshToken(String issuer, String username) {

        JwtClaims claims = new JwtClaims();
        //����refreshToken�����
        claims.setExpirationTimeMinutesInTheFuture(RefreshToken.REFRESH_TOKEN_VALIDITY_SECONDS);
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setIssuer(issuer);
        claims.setSubject(username);

        return claims;
    }
}
