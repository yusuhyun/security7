package io.security.corespringsecurity.security.service;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import io.security.corespringsecurity.domain.entity.Account;

public class AccountContext extends User {
	
	private final Account account;

    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(), authorities); //Account객체 사용하여 아이디 비번 전달
        this.account = account;
    }

    public Account getAccount() {
        return account;
    }
    
}
