package io.security.corespringsecurity.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import com.fasterxml.jackson.databind.ObjectMapper;

public class AjaxAuthenticationFailuerHandler implements AuthenticationFailureHandler {
	
	private ObjectMapper objectMapper = new ObjectMapper();
	
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException { // 인증실패했으므로 exception 받아옴
		
		String errMsg = "Invalid Username or Password-AjaxVer";
		
		response.setStatus(HttpStatus.UNAUTHORIZED.value());// 인증실패므로 UNAUTHORIZED
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		
		if(exception instanceof BadCredentialsException) { // 받은 익셉션 종류에따라 메세지 설정
			errMsg = "Invalid Username or Password-AjaxVer";
		}else if(exception instanceof DisabledException) { 
			errMsg = "Locked-AjaxVer";
		}else if(exception instanceof CredentialsExpiredException) { 
			errMsg = "Expired password-AjaxVer";
		}
		
		objectMapper.writeValue(response.getWriter(), errMsg); // 에러메세지 담아 보냄
		
	}

}
