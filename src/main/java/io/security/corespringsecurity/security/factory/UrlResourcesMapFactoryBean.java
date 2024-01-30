package io.security.corespringsecurity.security.factory;

import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import io.security.corespringsecurity.service.SecurityResourceService;

public class UrlResourcesMapFactoryBean implements FactoryBean<LinkedHashMap<RequestMatcher,List<ConfigAttribute>>> { // DB에서 가져온 정보를 resourceMap을 빈으로 생성후 metadataSource전달
	
	
	private SecurityResourceService securityResourceService; // db로부터 가져온 데이터를 매핑하는 service 호출
	private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourceMap;
	
	public void setSecurityResourceService(SecurityResourceService securityResourceService) {
		this.securityResourceService = securityResourceService;
	}
	
	@Override
	public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getObject() throws Exception { 
		
		if(resourceMap == null) { //널일경우 생성해야함
			init();
		}
		
		return resourceMap;
	}
	
	private void init() {
		resourceMap = securityResourceService.getResourceList();
		System.out.println("*** UrlResourcesMapFactoryBean resourceMap : " + resourceMap);
	}

	@Override
	public Class<?> getObjectType() {
		return LinkedHashMap.class;
	}
	// 메모리에 단 하나만 존재할 수 있도록
	@Override
	public boolean isSingleton() {
		return true;
	}
	
}
