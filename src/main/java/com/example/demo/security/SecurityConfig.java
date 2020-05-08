package com.example.demo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails guest = User.withDefaultPasswordEncoder()
//                .username("guest")
//                .password("guestPass")
//                .roles("GUEST")
//                .build();
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("userPass")
//                .roles("USER")
//                .build();
//        UserDetails admin = User.withDefaultPasswordEncoder()
//                .username("admin")
//                .password("adminPass")
//                .roles("ADMIN")
//                .build();
//        return new InMemoryUserDetailsManager(guest, user, admin);
//    }

    private static final String ENCODED_PASSWORD_USER = "$2a$10$1CsnFMbzWq.kIooc/e6kkexvPElmFxJYasZbo.2KTpuuqIKnvumEe";  // userPass
    private static final String ENCODED_PASSWORD_ADMIN = "$2a$10$VTUmE6/.apXWbVYMk3VCh.ooWqGEWHPbNBOiFWoML.6vgQDYypDSe"; // adminPass

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .passwordEncoder(passwordEncoder())
                .withUser("user").password(ENCODED_PASSWORD_USER).roles("USER");
        auth.inMemoryAuthentication()
                .passwordEncoder(passwordEncoder())
                .withUser("admin").password(ENCODED_PASSWORD_ADMIN).roles("ADMIN");
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().and().authorizeRequests()
                .antMatchers(HttpMethod.GET, "/api/employees").permitAll()
                .antMatchers(HttpMethod.GET, "/api/employees/all").hasRole("ADMIN")
                .antMatchers(HttpMethod.POST, "/api/employees").hasAnyRole("USER", "ADMIN")
                .antMatchers(HttpMethod.DELETE, "/api/employees/").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET, "/api/departments").permitAll()
                .antMatchers(HttpMethod.GET, "/api/departments/all").hasRole("ADMIN")
                .antMatchers(HttpMethod.POST, "/api/departments").hasAnyRole("USER", "ADMIN")
                .antMatchers(HttpMethod.DELETE, "/api/departments/").hasRole("ADMIN")
                .and()
                .formLogin().permitAll()
                .and()
                .logout().permitAll()
                .and()
                .csrf().disable();
    }
}
