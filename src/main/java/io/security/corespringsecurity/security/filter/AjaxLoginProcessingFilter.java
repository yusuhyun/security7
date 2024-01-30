package io.security.corespringsecurity.security.filter;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.ObjectUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.security.corespringsecurity.domain.dto.AccountDto;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter { // ajax 용 필터,  "/api/login" 로와야 작동하게~
	
	//json 으로 온 정보 객체로 추춣 ㅐ담아야함
	private ObjectMapper objectMapper = new ObjectMapper();
	
	public AjaxLoginProcessingFilter() {
		super(new AntPathRequestMatcher("/api/login"));
	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		
		if(!isAjax(request)) { // ajax 아닌경우(아래)
			System.out.println("****ajax 아님!");
			throw new IllegalStateException("Authentication is not supported");
		}
		
		AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);

        if (ObjectUtils.isEmpty(accountDto.getUsername()) || ObjectUtils.isEmpty(accountDto.getPassword())) { //// StringUtils.isEmpty() 비솰성되서 ObjectUtils로 바꿈...*****
        	System.out.println("****ObjectUtils.isEmpty 안돌아감!");
            throw new AuthenticationServiceException("Username or Password not provided");
        }
        
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());// AjaxAuthenticationToken 첫번째 생성자
		
		return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
	}

	private boolean isAjax(HttpServletRequest request) {
		
		if("XMLHttpRequest".equals(request.getHeader("x-Requested-With"))) {
			System.out.println("****XMLHttpRequest 같음!(아이작이라는뜻)");
			return true;
		}
		return false;
	}

}
