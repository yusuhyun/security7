package io.security.corespringsecurity.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {
	
	private String errorPage;
	
	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException { // 인가예외를 받아옴
		
		String deniedUrl = errorPage + "?exception=" + accessDeniedException.getMessage(); // 에러페이지, 에러메세지 담기
		response.sendRedirect(deniedUrl);
		
	}
	
	public void setErrorPage(String errorPage) {
		this.errorPage = errorPage;
	}
}
