package com.mylearning.mysec.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.mylearning.mysec.filter.JwtFilter;
import com.mylearning.mysec.service.CustomUserDetailsService;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtFilter jwtFilter;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    	// here you just need to create your own custom UserDetailsService and you need to fetch the User object based on the incomming request which will be username and password
        auth.userDetailsService(userDetailsService);	
    }
    //if we are using spring 2.x version then we need PasswordEncoder if we are using spring lower than 2.x then we don't need PasswordEncoder
    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        		http.csrf().disable()										// for this url disable csrf
        		.authorizeRequests().antMatchers("/authenticate")	// authorize requests matching the specified mapped url as per endpoint of controller
                .permitAll().anyRequest().authenticated()			// permit all with any request who is authenticated 
                .and().exceptionHandling()							// exceptionHandling
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);	// create session policy and managing session..... enabling the session policy which is stateless since JWT is following stateless authentication mechanism
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);	// we are registering the JwtFilter in our security configuration
    }
}
