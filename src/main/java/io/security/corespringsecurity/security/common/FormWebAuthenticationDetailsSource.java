package io.security.corespringsecurity.security.common;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@Component
public class FormWebAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> { //FormWebAuthenticationDetails 를 생성
	
    @Override
    public WebAuthenticationDetails buildDetails(HttpServletRequest request) {
        return new FormWebAuthenticationDetails(request);
    }
}
