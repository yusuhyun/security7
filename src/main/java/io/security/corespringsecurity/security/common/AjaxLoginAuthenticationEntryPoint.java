package io.security.corespringsecurity.security.common;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

public class AjaxLoginAuthenticationEntryPoint implements AuthenticationEntryPoint { // 인증된 사용자가 아닐경우
	
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException { // 인증객체 받아옴
		System.out.println("인증이 안됌 AJAX***");
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED,"UnAuthorized"); // 오류와 오류메세지 반환
		
	}

}
