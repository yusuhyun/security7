package io.security.corespringsecurity.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.security.corespringsecurity.domain.entity.Account;

public class AjaxAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
	
	private ObjectMapper objectMapper = new ObjectMapper();
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException { // 인증 성공정보 가져옴
			
		Account account = (Account)authentication.getPrincipal(); //받아온 정보가 account
		
		// account객체를 클라이언트로 응답
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		
		objectMapper.writeValue(response.getWriter(), account); // objectMapper 가 json형식으로 바꾸어 account 객체 전달
	}

}
