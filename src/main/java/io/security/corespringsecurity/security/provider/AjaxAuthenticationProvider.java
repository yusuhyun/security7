package io.security.corespringsecurity.security.provider;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import io.security.corespringsecurity.security.common.FormWebAuthenticationDetails;
import io.security.corespringsecurity.security.service.AccountContext;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;

public class AjaxAuthenticationProvider implements AuthenticationProvider{ 
	//구현부가 form 인증방식에서 작성했던것 일ㄹ단 복붙 + 차이점 : 인증객체(ajax token)
	//실제 인증처리하는 클래스 AjaxAuthenticationProvider
	
	@Autowired
	private UserDetailsService userDetailsService;
	@Autowired
	private PasswordEncoder passwordEncoder; 
	
//	public AjaxAuthenticationProvider(PasswordEncoder passwordEncoder) { 
//        this.passwordEncoder = passwordEncoder;
//    }
	
	@Override
	@Transactional
	public Authentication authenticate(Authentication authentication) throws AuthenticationException { // 사용자 정보(인증객체) 받아옴
		
		String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();
        System.out.println("******loginId // password: " + loginId + "//" + password + "** Ajax 버전 ***");
        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(loginId);

        if (!passwordEncoder.matches(password, accountContext.getPassword())) { // 패스워드 인증 실패시
        	System.out.println("**비번안됌");
            throw new BadCredentialsException("Invalid password");
        }
        
        //로그인시 추가입력정보(여기선 secret_key) 검사 ajax 버전에선 생략~
//        FormWebAuthenticationDetails formWebAuthenticationDetails = (FormWebAuthenticationDetails)authentication.getDetails();
//        String secretKey = formWebAuthenticationDetails.getSecretKey();
////        System.out.println("******secretKey: " +secretKey);
//        if(secretKey == null || !"secret".equals(secretKey)) {// secretKey가 일치하지 않을경우
//        	System.out.println("**secretKey 일치안함");
//        	throw new InsufficientAuthenticationException("InsufficientAuthenticationException");
//        }
        
        
        return new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities()); // 인증 성공시 토큰을 만듬 + ajax 버전
	}
	
	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(AjaxAuthenticationToken.class); // ajaxToken 으로 적용
	}
	
	
}
