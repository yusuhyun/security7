package io.security.corespringsecurity.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

public class AjaxAccessDeniedHandler implements AccessDeniedHandler { // 인증된 사용자가 자격이 없는경우
	
	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		System.out.println("인증은 됬는데 자격이 없음 AJAX***");
		response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access is Denied");
	}
}
