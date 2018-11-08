package com.soauth.server.service.business;

import com.soauth.core.vo.oauth2.AccessToken;
import com.soauth.core.vo.oauth2.ClientDetails;
import com.soauth.server.oauth.SoauthAuthRequest;
import org.jose4j.jwt.JwtClaims;

/**
 * @author zhoujie
 * @date 2017/12/8
 */
public class ImplicitAccessToken extends AbstractOIDCHolder {

    public AccessToken createNewAccessToken(ClientDetails clientDetails, SoauthAuthRequest rquest, boolean includeRefreshToken) {

        final String username = currentUser();
        AccessToken accessToken;

        JwtClaims claims = new JwtClaims();

        // value÷µΩ‚ Õ:http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        claims.setIssuer(null);
        claims.setAudience(clientDetails.getClientId());
        claims.setSubject(username);
        claims.setIssuedAtToNow();
        claims.setGeneratedJwtId();

        accessToken = tokenBuilder.enhance(clientDetails, claims, rquest, null);
        return accessToken;
    }
}
