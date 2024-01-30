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
import lombok.extern.slf4j.Slf4j;
@Slf4j
public class FormAuthenticationProvider implements AuthenticationProvider {
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	private PasswordEncoder passwordEncoder;
	
	public FormAuthenticationProvider(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
	
	@Override
	@Transactional
	public Authentication authenticate(Authentication authentication) throws AuthenticationException { // 사용자 정보 받아옴
		
		String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();
        System.out.println("******loginId // password: " + loginId + "//" + password);
        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(loginId);

        if (!passwordEncoder.matches(password, accountContext.getPassword())) { // 패스워드 인증 실패시
        	System.out.println("**비번안됌");
            throw new BadCredentialsException("Invalid password");
        }
        
        //로그인시 추가입력정보(여기선 secret_key) 검사
        FormWebAuthenticationDetails formWebAuthenticationDetails = (FormWebAuthenticationDetails)authentication.getDetails();
        String secretKey = formWebAuthenticationDetails.getSecretKey();
//        System.out.println("******secretKey: " +secretKey);
        if(secretKey == null || !"secret".equals(secretKey)) {// secretKey가 일치하지 않을경우
        	System.out.println("**secretKey 일치안함");
        	throw new InsufficientAuthenticationException("InsufficientAuthenticationException");
        }
        
        
        return new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities()); // 인증 성공시 토큰을 만듬
	}
	
	@Override
	public boolean supports(Class<?> authentication) {
		// TODO Auto-generated method stub
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}
}
