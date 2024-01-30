package io.security.corespringsecurity.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

@Component
public class FormAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
	
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		
		//받아온 예외를 처리
		String errorMessage = "Invalid Username or Password";
		if(exception instanceof BadCredentialsException) { // 받은 익셉션 종류에따라 메세지 설정
			errorMessage = "Invalid Username or Password";
		}else if(exception instanceof InsufficientAuthenticationException) { // secretKey 오류일경우 발생하게 설정해놓은 exception 가져와졌을시
			errorMessage = "Invalid Secret Key";
		}
		
		setDefaultFailureUrl("/login?error=true&exception=" + exception.getMessage()); // 실패시 url주소 추후 권한없어도 이동가능하도록 "/login*" 로 설정 해주어야함***
		
		super.onAuthenticationFailure(request, response, exception);
		
	}
}
