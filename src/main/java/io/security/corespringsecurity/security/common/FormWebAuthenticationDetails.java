package io.security.corespringsecurity.security.common;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

public class FormWebAuthenticationDetails extends WebAuthenticationDetails {
	
	private  String secretKey;

    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        secretKey = request.getParameter("secret_key"); // 추가로 받아오는 정보 저장
    }

    public String getSecretKey() {

        return secretKey;
    }
}
