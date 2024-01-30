package io.security.corespringsecurity.security.listener;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import io.security.corespringsecurity.domain.entity.AccessIp;
import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.domain.entity.RoleHierarchy;
import io.security.corespringsecurity.repository.AccessIpRepository;
import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.repository.RoleHierarchyRepository;
import io.security.corespringsecurity.repository.RoleRepository;
import io.security.corespringsecurity.repository.UserRepository;

@Component
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> { // 기본정보 생성

//    private boolean alreadySetup = false;
//
//    @Autowired
//    private UserRepository userRepository;
//
//    @Autowired
//    private RoleRepository roleRepository;
//
//    @Autowired
//    private ResourcesRepository resourcesRepository;
//
//    @Autowired
//    private PasswordEncoder passwordEncoder;
//
//    private static AtomicInteger count = new AtomicInteger(0);
//
//    @Override
//    @Transactional
//    public void onApplicationEvent(final ContextRefreshedEvent event) {
//
//        if (alreadySetup) {
//            return;
//        }
//
//        setupSecurityResources();
//
//        alreadySetup = true;
//    }
//
//
// 
//    private void setupSecurityResources() {
//    	System.out.println("****테스트정보 입력*****");
//        Set<Role> roles = new HashSet<>();
//        Role adminRole = createRoleIfNotFound("ROLE_ADMIN", "관리자");
//        roles.add(adminRole);
//        createResourceIfNotFound("/admin/**", "", roles, "url");
//        Account account = createUserIfNotFound("admin", "pass", "admin@gmail.com", 10,  roles);
//        
//        Set<Role> roles1 = new HashSet<>();
//
//        Role managerRole = createRoleIfNotFound("ROLE_MANAGER", "매니저");
//        roles1.add(managerRole);
//        createResourceIfNotFound("io.security.corespringsecurity.aopsecurity.method.AopMethodService.methodTest", "", roles1, "method");
//        createResourceIfNotFound("io.security.corespringsecurity.aopsecurity.method.AopMethodService.innerCallMethodTest", "", roles1, "method");
//        createResourceIfNotFound("execution(* io.security.corespringsecurity.aopsecurity.pointcut.*Service.*(..))", "", roles1, "pointcut");
//        createUserIfNotFound("manager", "pass", "manager@gmail.com", 20, roles1);
//
//        Set<Role> roles3 = new HashSet<>();
//
//        Role childRole1 = createRoleIfNotFound("ROLE_USER", "회원");
//        roles3.add(childRole1);
//        createResourceIfNotFound("/users", "", roles3, "url");
//        createUserIfNotFound("user", "pass", "user@gmail.com", 30, roles3);
//
//    }
//
//    @Transactional
//    public Role createRoleIfNotFound(String roleName, String roleDesc) {
//
//        Role role = roleRepository.findByRoleName(roleName);
//
//        if (role == null) {
//            role = Role.builder()
//                    .roleName(roleName)
//                    .roleDesc(roleDesc)
//                    .build();
//        }
//        return roleRepository.save(role);
//    }
//
//    @Transactional
//    public Account createUserIfNotFound(String userName, String password, String email, int age, Set<Role> roleSet) {
//
//        Account account = userRepository.findByUsername(userName);
//
//        if (account == null) {
//            account = Account.builder()
//                    .username(userName)
//                    .email(email)
//                    .age(age)
//                    .password(passwordEncoder.encode(password))
//                    .userRoles(roleSet)
//                    .build();
//        }
//        return userRepository.save(account);
//    }
//
//    @Transactional
//    public Resources createResourceIfNotFound(String resourceName, String httpMethod, Set<Role> roleSet, String resourceType) {
//        Resources resources = resourcesRepository.findByResourceNameAndHttpMethod(resourceName, httpMethod);
//
//        if (resources == null) {
//            resources = Resources.builder()
//                    .resourceName(resourceName)
//                    .roleSet(roleSet)
//                    .httpMethod(httpMethod)
//                    .resourceType(resourceType)
//                    .orderNum(count.incrementAndGet())
//                    .build();
//        }
//        return resourcesRepository.save(resources);
//    }
    
//    
    private boolean alreadySetup = false;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private ResourcesRepository resourcesRepository;

    @Autowired
    private RoleHierarchyRepository roleHierarchyRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AccessIpRepository accessIpRepository;

    private static AtomicInteger count = new AtomicInteger(0);

    @Override
    @Transactional
    public void onApplicationEvent(final ContextRefreshedEvent event) {

        if (alreadySetup) {
            return;
        }

        setupSecurityResources();

//        setupAccessIpData(); 

        alreadySetup = true;
    }



    private void setupSecurityResources() {
        Set<Role> roles = new HashSet<>();
        Set<Role> roles1 = new HashSet<>();
        Set<Role> roles3 = new HashSet<>();
        
        Role adminRole = createRoleIfNotFound("ROLE_ADMIN", "관리자");
        Role managerRole = createRoleIfNotFound("ROLE_MANAGER", "매니저권한");
        Role userRole = createRoleIfNotFound("ROLE_USER", "사용자권한");
        
        createUserIfNotFound("admin", "admin@admin.com", "pass", roles);
        createUserIfNotFound("manager", "manager@gmail.com", "pass", roles1);
        createUserIfNotFound("user", "user@gmail.com", "pass",roles3);
        roles.add(adminRole);
        roles1.add(managerRole);
        roles3.add(userRole);
        
        createResourceIfNotFound("/admin/**", "", roles, "url");
        createResourceIfNotFound("/mypage", "", roles3, "url");
        createResourceIfNotFound("/messages", "", roles1, "url");
        createResourceIfNotFound("/config", "", roles, "url");
        
        createRoleHierarchyIfNotFound(managerRole, adminRole);
        createRoleHierarchyIfNotFound(userRole, managerRole);
        
        
//	    createResourceIfNotFound("io.security.corespringsecurity.aopsecurity.method.AopMethodService.methodTest", "", roles1, "method");
//	    createResourceIfNotFound("io.security.corespringsecurity.aopsecurity.method.AopMethodService.innerCallMethodTest", "", roles1, "method");
//	    createResourceIfNotFound("execution(* io.security.corespringsecurity.aopsecurity.pointcut.*Service.*(..))", "", roles1, "pointcut");


    }

    @Transactional
    public Role createRoleIfNotFound(String roleName, String roleDesc) {

        Role role = roleRepository.findByRoleName(roleName);

        if (role == null) {
            role = Role.builder()
                    .roleName(roleName)
                    .roleDesc(roleDesc)
                    .build();
        }
        return roleRepository.save(role);
    }

    @Transactional
    public Account createUserIfNotFound(final String userName, final String email, final String password, Set<Role> roleSet) {

        Account account = userRepository.findByUsername(userName);

        if (account == null) {
            account = Account.builder()
                    .username(userName)
                    .email(email)
                    .password(passwordEncoder.encode(password))
                    .userRoles(roleSet)
                    .build();
        }
        return userRepository.save(account);
    }

    @Transactional
    public Resources createResourceIfNotFound(String resourceName, String httpMethod, Set<Role> roleSet, String resourceType) {
        Resources resources = resourcesRepository.findByResourceNameAndHttpMethod(resourceName, httpMethod);

        if (resources == null) {
            resources = Resources.builder()
                    .resourceName(resourceName)
                    .roleSet(roleSet)
                    .httpMethod(httpMethod)
                    .resourceType(resourceType)
                    .orderNum(count.incrementAndGet())
                    .build();
        }
        return resourcesRepository.save(resources);
    }

    @Transactional
    public void createRoleHierarchyIfNotFound(Role childRole, Role parentRole) {

        RoleHierarchy roleHierarchy = roleHierarchyRepository.findByChildName(parentRole.getRoleName());
        if (roleHierarchy == null) {
            roleHierarchy = RoleHierarchy.builder()
                    .childName(parentRole.getRoleName())
                    .build();
        }
        RoleHierarchy parentRoleHierarchy = roleHierarchyRepository.save(roleHierarchy);

        roleHierarchy = roleHierarchyRepository.findByChildName(childRole.getRoleName());
        if (roleHierarchy == null) {
            roleHierarchy = RoleHierarchy.builder()
                    .childName(childRole.getRoleName())
                    .build();
        }

        RoleHierarchy childRoleHierarchy = roleHierarchyRepository.save(roleHierarchy);
        childRoleHierarchy.setParentName(parentRoleHierarchy);
    }

//    private void setupAccessIpData() {
//        AccessIp byIpAddress = accessIpRepository.findByIpAddress("127.0.0.1");
//        if (byIpAddress == null) {
//            AccessIp accessIp = AccessIp.builder()
//                    .ipAddress("127.0.0.1")
//                    .build();
//            accessIpRepository.save(accessIp);
//        }
//    }
    
    private void setupAccessIpData() {
        AccessIp byIpAddress = accessIpRepository.findByIpAddress("0:0:0:0:0:0:0:1");
        if (byIpAddress == null) {
            AccessIp accessIp = AccessIp.builder()
                    .ipAddress("0:0:0:0:0:0:0:1")
                    .build();
            AccessIp accessIp2 = AccessIp.builder()
                    .ipAddress("127:0:1")
                    .build();
            accessIpRepository.save(accessIp);
        }
    }
    
}
