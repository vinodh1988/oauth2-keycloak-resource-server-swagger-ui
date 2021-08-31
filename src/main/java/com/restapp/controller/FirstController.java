package com.restapp.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FirstController {
	
	@RequestMapping("/")
	public String home(){
		
		return "Rest API server is running on 8899";
	}

}
