package io.security.corespringsecurity.security.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.repository.UserRepository;

@Service("userDetailService")
public class CustomUserDetailsService implements UserDetailsService{
	
	@Autowired
	private UserRepository userRepository;
	
	@Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Account account = userRepository.findByUsername(username);

        if (account == null) {
            if (userRepository.countByUsername(username) == 0) {
                throw new UsernameNotFoundException("No user found with username: " + username);
            }
        }
        
        List<GrantedAuthority> collect = account.getUserRoles()
                .stream()
                .map(userRole -> userRole.getRoleName())
                .collect(Collectors.toSet())
                .stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        //List<GrantedAuthority> collect = userRoles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return new AccountContext(account, collect);
        
//        List<GrantedAuthority> roles = new ArrayList<>(); 
//        roles.add(new SimpleGrantedAuthority(account.getRole()));
//
//        AccountContext accountContext = new AccountContext(account, roles);// 컬렉션타입의 권한정보 roles으로 가져오기
//
//        return accountContext;
    }

}
