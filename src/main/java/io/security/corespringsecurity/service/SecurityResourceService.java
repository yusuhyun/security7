package io.security.corespringsecurity.service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.AccessIpRepository;
import io.security.corespringsecurity.repository.ResourcesRepository;
import lombok.extern.slf4j.Slf4j;
@Slf4j
public class SecurityResourceService {
	
	private ResourcesRepository resourcesRepository;
	private AccessIpRepository accessIpRepository;
	
//	public void setResourcesRepository(ResourcesRepository resourcesRepository) {
//		this.resourcesRepository = resourcesRepository;
//	}
	
	public SecurityResourceService(ResourcesRepository resourcesRepository,AccessIpRepository accessIpRepository) {
		this.resourcesRepository = resourcesRepository;
		this.accessIpRepository = accessIpRepository;
	}


	public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() { //DB로부터 권한,자원 가져와 매핑
		
		LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
		List<Resources> resourcesList = resourcesRepository.findAllResources(); // db의 리소스 모든자원 가져옴
		System.out.println("****(DB에서 가져온 Resource리스트) resourcesList : " + resourcesList);
		
		resourcesList.forEach(re -> { //리소스 하나당 권한정보 돌림
			List<ConfigAttribute> configAttributeList = new ArrayList<>();
			re.getRoleSet().forEach(role -> { //역할 하나당 가져온 권한정보들 쭉 넣음
				configAttributeList.add(new SecurityConfig(role.getRoleName())); 
				result.put(new AntPathRequestMatcher(re.getResourceName()), configAttributeList); // LinkedHashMap 반환타입으로 key에 해당하는 자원정보,값에 매핑된 권한리스트 넣음
			});
		});
		return result;
	}


	public List<String> getAccessIpList() {
		
		List<String> accessIpList = accessIpRepository.findAll().stream().map(accessIp -> accessIp.getIpAddress()).collect(Collectors.toList());
		
		return accessIpList;
		
	}

}
