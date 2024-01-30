package io.security.corespringsecurity.security.configs;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;

import io.security.corespringsecurity.security.common.FormWebAuthenticationDetailsSource;
import io.security.corespringsecurity.security.factory.UrlResourcesMapFactoryBean;
import io.security.corespringsecurity.security.filter.PermitAllFilter;
import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import io.security.corespringsecurity.security.provider.FormAuthenticationProvider;
import io.security.corespringsecurity.security.voter.IpAddressVoter;
import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableWebSecurity
@Slf4j
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private AuthenticationSuccessHandler formAuthenticationSuccessHandler;//커스텀 성공 핸들러
	@Autowired
	private AuthenticationFailureHandler formAuthenticationFailureHandler; //커스텀 실패 핸들러
	@Autowired
	private FormWebAuthenticationDetailsSource formWebAuthenticationDetailsSource;// 로그인시 추가입력정보 저장
	@Autowired
	private SecurityResourceService securityResourceService;
	
	private String[] permitAllResources = {"/","/home","/h2/**","/users","/login*"}; //permitAll로 넘길 권한검사 할 필요 없는 자원
//	@Autowired
//	private UserDetailsService userDetailService;
	
	
	
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        String password = passwordEncoder().encode("1111");
//        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");
//        auth.inMemoryAuthentication().withUser("manager").password(password).roles("USER","MANAGER");
//        auth.inMemoryAuthentication().withUser("admin").password(password).roles("USER","MANAGER","ADMIN");
    	
//    	auth.userDetailsService(userDetailService);
    	auth.authenticationProvider(authenticationProvider());
    }
    
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception{
    	
    	return super.authenticationManagerBean();
    }
    
    @Bean
    public AuthenticationProvider authenticationProvider(){
        return new FormAuthenticationProvider(passwordEncoder());
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Override
    protected void configure(final HttpSecurity http) throws Exception {
    	
    	System.out.println("SecurityConfig***");
        http
				.csrf()
		        .ignoringAntMatchers("/h2/**")
		.and()
				.headers()
				.addHeaderWriter(new XFrameOptionsHeaderWriter(XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN))
		.and()
                .authorizeRequests()
//                .antMatchers("/","/home","/h2/**","/users","/login*").permitAll()
//                .antMatchers("/mypage").hasRole("USER")
//                .antMatchers("/messages","/api/messages").hasRole("MANAGER")
//                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
        .and()
		        .formLogin()
		        .loginPage("/login")
		        .loginProcessingUrl("/login_proc")
		        .defaultSuccessUrl("/home")
		        .authenticationDetailsSource(formWebAuthenticationDetailsSource) //로그인시 추가정보도 받아 검사하도록 커스텀
		        .successHandler(formAuthenticationSuccessHandler)
		        .failureHandler(formAuthenticationFailureHandler)
		        .permitAll()
        .and()	
        		.exceptionHandling()
        		.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
        		.accessDeniedPage("/denied")
        		.accessDeniedHandler(accessDeniedHandler())
		.and()
				.addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class) // 커스텀을 먼저 실행하도록.. (한번 인가처리 실행되면 기존것은 실행되지 x)
        		;
				
    }
    
    public AccessDeniedHandler accessDeniedHandler() {
    	CustomAccessDeniedHandler accessDeniedhandler = new CustomAccessDeniedHandler(); //커스텀한 미인가 처리 핸들러 
    	accessDeniedhandler.setErrorPage("/denied");
    	return accessDeniedhandler;
    }
    
    @Override
    public void configure(WebSecurity web) throws Exception {
    	web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations()); // permitAll() 과 비슷하나 아예 보안필터 거치지 x
    }
    
    
    //UrlFilterInvocationSecurityMetadataSource 사용위한 필터 추가
    @Bean
    public FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception{ // FilterSecurityInterceptor -> PermitAllFilter 직접 작성한 필터로 변경 
    	
//    	PermitAllFilter permitAllFilter = new PermitAllFilter(permitAllResources); //3가지 값 설정해야함
//    	permitAllFilter.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource()); // 
//    	permitAllFilter.setAccessDecisionManager(affirmaticeBased()); // 접근 결정 관리자, affirmaticeBased(): 여러개의 Voter클래스중 하나라도 허가일 경우 최종 접근허가로 판단
//    	permitAllFilter.setAuthenticationManager(authenticationManagerBean()); //인증관리자 
//    	return permitAllFilter;
    	
    	FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor(); //3가지 값 설정해야함
    	filterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource()); // 
    	filterSecurityInterceptor.setAccessDecisionManager(affirmaticeBased()); // AccessDecisionManager: 접근 결정 관리자, affirmaticeBased(): 여러개의 Voter클래스중 하나라도 허가일 경우 최종 접근허가로 판단
    	filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean()); //인증관리자 
    	return filterSecurityInterceptor;
    }
    
	private AccessDecisionManager affirmaticeBased() {
		AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecistionVoters()); //AccessDecistionVoter : 판단을 심사해 manager로 넘김 - 인증정보(user), 요청정보(antMatcher), 권한정보(hasRole) 
		return affirmativeBased;
	}
    
    private List<AccessDecisionVoter<?>> getAccessDecistionVoters() {
    	
    	List<AccessDecisionVoter<? extends Object>> accessDecisionVoters = new ArrayList<>();
//    	accessDecisionVoters.add(new IpAddressVoter(securityResourceService)); // ipAddress가 제일먼저 체크되어야 함
    	accessDecisionVoters.add(roleVoter()); //RoleHierarchyVoter가 사용되어야함
    	
//		return Arrays.asList(new RoleVoter());
		return accessDecisionVoters;
	}
    
    @Bean
	public AccessDecisionVoter<? extends Object> roleVoter() {
    	
    	RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarchy());
    	
		return roleHierarchyVoter;
	}

    @Bean
	public RoleHierarchyImpl roleHierarchy() {
    	
    	RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
    	System.out.println("***** roleHierarchy : " + roleHierarchy);
		return roleHierarchy;
	}

	@Bean
	public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() throws Exception {
		return new UrlFilterInvocationSecurityMetadataSource(urlResourcesMapFactoryBean().getObject(), securityResourceService);
	}
    
    private UrlResourcesMapFactoryBean urlResourcesMapFactoryBean(){
    	UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
    	urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
    	
    	return urlResourcesMapFactoryBean;
    }
    
    
    
    
    
    
    
    
}


