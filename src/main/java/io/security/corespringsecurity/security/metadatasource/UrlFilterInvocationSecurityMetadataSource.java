package io.security.corespringsecurity.security.metadatasource;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class UrlFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource { 
	
	private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap; // 순서도 저장하기위해 LinkedHashMap 사용
	private SecurityResourceService securityResourceService;
	
	
	public UrlFilterInvocationSecurityMetadataSource(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourcesMap, SecurityResourceService securityResourceService) {
		this.requestMap = resourcesMap; // 키(url), 값(접근가능 권한정보) 가져옴 
		this.securityResourceService = securityResourceService; // 변경시 다시 불러오기위해 사용
	}

	@Override
	public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException { //url, 메소드 둘다 받아서 Object사용..
		
		System.out.println("*** UrlFilterInvocationSecurityMetadataSource object : " + object);
		System.out.println("***requestMap : " + requestMap); 
		HttpServletRequest request = ((FilterInvocation) object).getRequest(); // 받아온 object 타입캐스팅~, 사용자의 요청 url 확인
		
		// 임시로 직접 권한 정보 추가
//		requestMap.put(new AntPathRequestMatcher("/mypage"), Arrays.asList(new SecurityConfig("ROLE_USER")));
		
		if(requestMap != null) { // 권한정보 추출 로직
			for(Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()) { //RequestMatcher :db 에서 가져온 요청정보
				RequestMatcher matcher = entry.getKey();
				if(matcher.matches(request)) { // 사용자 요청정보와 저장정보 일치하면
					System.out.println("***********entry.getValue() : " + entry.getValue());
					return entry.getValue(); // 권한정보 리턴
				}
			};
		}
		
		
		return null;
	}

	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() { //FilterInvocationSecurityMetadataSource 내용 가져옴
		Set<ConfigAttribute> allAttributes = new HashSet<>();
		
		for(Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap
				.entrySet()) {
			allAttributes.addAll(entry.getValue());
		}
		
		return allAttributes;
	}
	
	@Override
	public boolean supports(Class<?> clazz) { //FilterInvocationSecurityMetadataSource 내용 가져옴
		return FilterInvocation.class.isAssignableFrom(clazz); //타입검사
	}
	
	public void reload() { // db 리소스 추가/변경시 값 다시가져옴..
		
		LinkedHashMap<RequestMatcher, List<ConfigAttribute>> reloadeMap = securityResourceService.getResourceList();
		Iterator<Map.Entry<RequestMatcher,List<ConfigAttribute>>> iterator = reloadeMap.entrySet().iterator();
		
		requestMap.clear(); //업데이트 이전정보 삭제
		
		while(iterator.hasNext()) {
			Map.Entry<RequestMatcher, List<ConfigAttribute>> entry = iterator.next();
			requestMap.put(entry.getKey(), entry.getValue());// 가져온 정보 새로 채워줌...
		}
		
	}
	
	
	

}
