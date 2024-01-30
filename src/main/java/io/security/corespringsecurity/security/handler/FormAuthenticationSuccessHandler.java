package io.security.corespringsecurity.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;
@Component
public class FormAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
	
	private RequestCache requestCache = new HttpSessionRequestCache(); // 사용자가 거쳐온 세션정보를 가져옴
	
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy(); // 
	
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException { //로그인 성공 이후 처리
		
		setDefaultTargetUrl("/"); // 기본 url 설정
		
		SavedRequest savedRequest = requestCache.getRequest(request, response); //거쳐왔던 요청정보 가져오기
		if(savedRequest != null) { // 로그인전 요청정보 있을경우 해당 url 이동
			String targetUrl = savedRequest.getRedirectUrl();
			redirectStrategy.sendRedirect(request, response, targetUrl);
		} else { // 로그인전 요청 정보 없을경우 이동할 기본페이지 지정
			redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl()); // 기본설정해놓은 url로 이동
		}
		
		
	}
	
	
}
