package com.soauth.server.shiro;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * @author zhoujie
 * @date 2017/12/8
 */
public class UserInfoFilter extends AuthenticatingFilter {

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {

        final String token = getAccessToken((HttpServletRequest) request);


        return null;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return false;
    }


    /**
     * �ͻ���������Ȩ,������ѭrfc6750�ĵ��ύaccesstoken, ��ʹ��' Authorization' Handler��������, ��ʹ�� POST���� ��Content-Type����Ϊ application/x-www-form-urlencoded
     * <p>
     * document: https://tools.ietf.org/html/rfc6750#ref-W3C.REC-html401-19991224
     */
    private String getAccessToken(HttpServletRequest request) {
        String token = null;

        if (!StringUtils.isNotEmpty(request.getHeader(OAuth.HeaderType.AUTHORIZATION))) {

            return token = request.getHeader(OAuth.HeaderType.AUTHORIZATION).substring(6).trim();

        } else if (!request.getMethod().equals(OAuth.HttpMethod.POST) && !request.getContentType().equals(OAuth.ContentType.URL_ENCODED)) {
            return token = request.getParameter(OAuth.OAUTH_ACCESS_TOKEN);
        } else {
            return token;
        }

    }

}
