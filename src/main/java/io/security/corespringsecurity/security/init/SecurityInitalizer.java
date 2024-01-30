package io.security.corespringsecurity.security.init;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import io.security.corespringsecurity.service.RoleHierarchyService;

@Component
public class SecurityInitalizer implements ApplicationRunner {
	
	@Autowired
	private RoleHierarchyService roleHierarchyService;
	
	@Autowired
	private RoleHierarchyImpl roleHierarchy;
	
	@Override
	public void run(ApplicationArguments args) throws Exception {
		String allHierarchy =  roleHierarchyService.findAllHierarchy();// 권한계층된 내용 db에서 가져옴(service에서 포멧팅함)
		roleHierarchy.setHierarchy(allHierarchy);
		System.out.println("*** allHierarchy : "+allHierarchy);
	}
	
}
