package io.security.corespringsecurity.security.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class PermitAllFilter extends FilterSecurityInterceptor { // FilterSecurityInterceptor 내용 일부 가져와 사용
	
	private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
	private boolean observeOncePerRequest = true;
	
	private List<RequestMatcher> permitAllRequestMatchers = new ArrayList<>(); // ()사용자요청정보와 matches로 일치하는지 비교위해 RequestMatcher타입으로 저장
	
	// 생성자에서 인증,인가 필요없는 자원 전달받기
	public PermitAllFilter(String...permitAllResources) {
		
		for(String resource : permitAllResources) { //들어온 리소스들을 저장
			permitAllRequestMatchers.add(new AntPathRequestMatcher(resource)); 
		}
		
	}
	
	@Override
	protected InterceptorStatusToken beforeInvocation(Object object) { // 아래에서 처리되기전 실행됨
		// 인가처리로 들어가기전 permitAll 설정
		boolean permitAll = false;
		HttpServletRequest request = ((FilterInvocation)object).getRequest(); //request 정보 가져옴
		
		for(RequestMatcher requestMatcher : permitAllRequestMatchers) {// 사용자정보와 위 가져온 리소스 일치하는지 확인
			if(requestMatcher.matches(request)) {//일치하면 인가처리 갈 필요x
				permitAll = true;
				break;
			}
		}
		
		if(permitAll) {
			return null; //권한 심사하지 않음
		}
		
		return super.beforeInvocation(object); // 위 과정에서 걸러지지 않은경우 인가처리하러 감
	}

	public void invoke(FilterInvocation fi) throws IOException, ServletException { //사용자의 요청정보를 받아와 처리함
		
		if((fi.getRequest() != null) && (fi.getRequest().getAttribute(FILTER_APPLIED) != null) && observeOncePerRequest) {
			fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
		} else {
			if (fi.getRequest() != null && this.observeOncePerRequest) {
				fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
			}
			InterceptorStatusToken token = beforeInvocation(fi);
			try {
				fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
			}
			finally {
				super.finallyInvocation(token);
			}
			super.afterInvocation(token, null);
		}
		
	}

//	public void invoke(FilterInvocation filterInvocation) throws IOException, ServletException {
//		if (isApplied(filterInvocation) && this.observeOncePerRequest) {
//			// filter already applied to this request and user wants us to observe
//			// once-per-request handling, so don't re-do security checking
//			filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
//			return;
//		}
//		// first time this request being called, so perform security checking
//		if (filterInvocation.getRequest() != null && this.observeOncePerRequest) {
//			filterInvocation.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
//		}
//		InterceptorStatusToken token = beforeInvocation(filterInvocation);
//		try {
//			filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
//		}
//		finally {
//			super.finallyInvocation(token);
//		}
//		super.afterInvocation(token, null);
//	}
//
//	private boolean isApplied(FilterInvocation filterInvocation) {
//		return (filterInvocation.getRequest() != null)
//				&& (filterInvocation.getRequest().getAttribute(FILTER_APPLIED) != null);
//	}
//
//	
//	public boolean isObserveOncePerRequest() {
//		return this.observeOncePerRequest;
//	}
//
//	public void setObserveOncePerRequest(boolean observeOncePerRequest) {
//		this.observeOncePerRequest = observeOncePerRequest;
//	}
	
}
