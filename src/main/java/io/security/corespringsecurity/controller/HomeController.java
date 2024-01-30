package io.security.corespringsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import lombok.extern.slf4j.Slf4j;

@Controller
public class HomeController {
	
	@GetMapping(value={"/","/home"})
	public String home() throws Exception {
		return "home";
	}

}
