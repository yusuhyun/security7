package io.security.corespringsecurity.security.voter;

import java.util.Collection;
import java.util.List;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import io.security.corespringsecurity.service.SecurityResourceService;

public class IpAddressVoter implements AccessDecisionVoter<Object> {
	
	private SecurityResourceService securityResourceService;
	
	public IpAddressVoter(SecurityResourceService securityResourceService) {
		this.securityResourceService = securityResourceService;
	}

	@Override
	public boolean supports(ConfigAttribute attribute) {
		// TODO Auto-generated method stub
		return true;
	}
	
	@Override
	public boolean supports(Class<?> clazz) {
		// TODO Auto-generated method stub
		return true;
	}
	
	@Override
	public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
		// 순서대로 사용자 인증객체 정보, 요청정보, 자원 접근시 필요한 권한정보(filterInvocation에서 가져온)
		
		WebAuthenticationDetails details = (WebAuthenticationDetails)authentication.getDetails(); // 사용자의 ip정보를 얻을 수 있음
		String remoteAddress = details.getRemoteAddress(); // 사용자 ip
		
		List<String> accessIpList = securityResourceService.getAccessIpList();
		
		int result = ACCESS_DENIED;
		System.out.println("****remoteAddress : " + remoteAddress);
		System.out.println("****ipAddress : " + accessIpList);
		for(String ipAddress : accessIpList) {
			if(remoteAddress.equals(ipAddress)) {
				return ACCESS_ABSTAIN; // 허용 되는 ip더라도 해당 자원에대한 인가가 있는지 체크해야 함으로 바로 승인처리는 하지 x
			}
		}
		
		if(result == ACCESS_DENIED) { //허용x ip인경우 아예 다음 인증과정도 가지않도록 바로 거부처리
			throw new AccessDeniedException("Invalid IpAddress");
		}
		
		
		return 0;
	}
	
}
