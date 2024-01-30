package io.security.corespringsecurity.security.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import io.security.corespringsecurity.security.common.AjaxLoginAuthenticationEntryPoint;
import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.security.handler.AjaxAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationFailuerHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;

@Configuration
@Order(0) //스프링 시큐리티 초기화시 설정클래스 순서 세팅해줘야 함
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter { // ajax용 config
	
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception { 
		auth.authenticationProvider(ajaxAuthenticationProvider());//ajax용 Provider 적용함 
	}
	@Bean
	public AuthenticationProvider ajaxAuthenticationProvider() {
		return new AjaxAuthenticationProvider();
	}
	
	@Bean
	public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
		return new AjaxAuthenticationSuccessHandler(); //ajax 커스텀
	}
	@Bean
	public AuthenticationFailureHandler ajaxAuthenticationFailureHandler() {
		return new AjaxAuthenticationFailuerHandler(); //ajax 커스텀
	}
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		System.out.println("AjaxSecurityConfig***");
		http
				.antMatcher("/api/**")//특정한 url정보에만 작동하도록 설정
				.authorizeHttpRequests()
				.antMatchers("/api/messages").hasRole("MANAGER")
				.anyRequest().authenticated()
		.and()
				.addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)//추가하는 필터가 기존필터 앞에 위치할때(ajax 필터) 
        ;
		http
				.exceptionHandling()
				.authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())//인증x 사용자가 접근시 
				.accessDeniedHandler(ajaxAccessDeniedHandler()) // 인증ㅇ 권한x 사용자 접근시
				.accessDeniedPage("/denied")
		;
		
        http.csrf().disable();
		
	}
	
	public AjaxAccessDeniedHandler ajaxAccessDeniedHandler() {
		return new AjaxAccessDeniedHandler();
	}
	
	@Bean
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception { //ajax으로 들어온 정보에 적용 될 필터 // SecurityConfig 있던것 ajaxConfig로 가져옴!
    	AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
    	ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManagerBean());
    	ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());// 핸들러 등록1
    	ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler());// 핸들러 등록2
    	return ajaxLoginProcessingFilter;
    	
    }
	
	
}
