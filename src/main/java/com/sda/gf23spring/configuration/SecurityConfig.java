package com.sda.gf23spring.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.sql.DataSource;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    DataSource dataSource;


    //    @Autowired
//    public void securityUsers(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("Robert")
//                .password("$2a$10$8JW0j4SWUViXOxko8k.ctO7U2T8uIYwnRS1O/ulcPd2HbgNc2AL2u")
//                .roles("ADMIN", "USER")
//                .and()
//                .withUser("ania")
//                .password("$2a$10$ONnFnoBl4Lc8T6SzD5iYe..As2qX8Ni8DFg4s364ifvCTE6fZ4ezS")
//                .roles("USER");
//    }
    @Autowired
    public void securityUsers(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .jdbcAuthentication()
                .dataSource(dataSource)
                .usersByUsernameQuery("select login, password, enabled from users where login = ?")
                .authoritiesByUsernameQuery("select login, role from user_role where login = ?");

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("h2-console/**")
                .permitAll()
                .antMatchers("/", "/spersons", "/sperson/**", "/sPersonsByAge", "/sByDate").hasAnyAuthority("ADMIN", "USER")
                .antMatchers("/addPerson", "/delPerson", "/modifyPerson/**", "/spersonsM").hasAnyAuthority("ADMIN")
                .anyRequest().authenticated()
                .and().formLogin()
                .and().logout();
        http.csrf().ignoringAntMatchers("/h2-console/**");
        http.headers().frameOptions().sameOrigin();

    }


    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    public void setDataSource(DataSource dataSource) {
        this.dataSource = dataSource;
    }
}
