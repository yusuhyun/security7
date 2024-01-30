package io.security.corespringsecurity.controller.login;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import io.security.corespringsecurity.domain.entity.Account;

@Controller
public class LoginController {

	@RequestMapping(value={"/login", "/api/login"})
	public String login(@RequestParam(value = "error", required = false) String error,
						@RequestParam(value = "exception", required = false) String exception, Model model){ // 로그인오류시 받아온 exception 메세지를 model에 담아 날리기
		
		model.addAttribute("error", error);
		model.addAttribute("exception",exception);
		
		return "login";
	}

	@GetMapping(value = "/logout")
	public String logout(HttpServletRequest request, HttpServletResponse response) throws Exception {

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication != null){
			new SecurityContextLogoutHandler().logout(request, response, authentication);
		}

		return "redirect:/login";
	}
	
	@GetMapping(value={"/denied","/api/denied"})
	public String accessDenied(@RequestParam(value = "exception", required = false) String exception, Model model) { //에러받아 model 담에 넘김
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); // 권한정보 받아옴
		Account account = (Account)authentication.getPrincipal();
		model.addAttribute("username", account.getUsername());
		model.addAttribute("exception", exception);
		
		return "/user/login/denied";
	}
}
