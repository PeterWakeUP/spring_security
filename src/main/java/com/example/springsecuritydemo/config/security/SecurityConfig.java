package com.example.springsecuritydemo.config.security;

import com.example.springsecuritydemo.config.security.access.MyInvocationSecurityMetadataSourceService;
import com.example.springsecuritydemo.config.security.handler.MyAccessDeniedHandler;
import com.example.springsecuritydemo.config.security.handler.MyLoginUrlAuthenticationEntryPoint;
import com.example.springsecuritydemo.config.security.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    protected AuthenticationSuccessHandler myAuthenticationSuccessHandler;

    @Autowired
    protected AuthenticationFailureHandler myAuthenticationFailureHandler;

    @Autowired
    protected MyLoginUrlAuthenticationEntryPoint myLoginUrlAuthenticationEntryPoint;

    @Autowired
    private MyAccessDeniedHandler myAccessDeniedHandler;

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    private MyInvocationSecurityMetadataSourceService myInvocationSecurityMetadataSourceService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()                    //  定义当需要用户登录时候，转到的登录页面。
                .loginPage("/login.html")           // 设置登录页面
                .loginProcessingUrl("/user/login")  // 自定义的登录接口
                .successHandler(myAuthenticationSuccessHandler)                                 // 认证成功回调
                .failureHandler(myAuthenticationFailureHandler)
                .and()
                .authorizeRequests()        // 定义哪些URL需要被保护、哪些不需要被保护
                .antMatchers("/login.html").permitAll()     // 设置所有人都可以访问登录页面
                .anyRequest().authenticated()               // 任何请求,登录后可以访问,这个如果有配MyInvocationSecurityMetadataSourceService则拦截其配置的拦截路径
                .and()
                .csrf().disable();          // 关闭csrf防护

        http.exceptionHandling().authenticationEntryPoint(myLoginUrlAuthenticationEntryPoint).accessDeniedHandler(myAccessDeniedHandler);
        //认证
        http.addFilterAt(usernamePasswordAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        //权限拦截
        http.addFilterAt(filterSecurityInterceptor(), FilterSecurityInterceptor.class);

    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//--------------------------------------认证----------------------------------------------------------------
    public UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter(){
        UsernamePasswordAuthenticationFilter authenticationFilter = new UsernamePasswordAuthenticationFilter();
        authenticationFilter.setPostOnly(false);
        authenticationFilter.setAuthenticationManager(authenticationManager());
        /*authenticationFilter.setAuthenticationSuccessHandler(myAuthenticationSuccessHandler);
        authenticationFilter.setAuthenticationFailureHandler(myAuthenticationFailureHandler);*/
        return authenticationFilter;
    }

    public AuthenticationManager authenticationManager(){
        List<AuthenticationProvider> list = new ArrayList<>();
        list.add(authenticationProvider());
        AuthenticationManager authenticationManager = new ProviderManager(list);
        return authenticationManager;
    }

    public DaoAuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();

        SpringSecurityMessageSource messageSource = new SpringSecurityMessageSource();
        messageSource.setAlwaysUseMessageFormat(true);
        messageSource.setBasename("message");

        provider.setMessageSource(messageSource);
        provider.setUserDetailsService(myUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder());

        return provider;
    }
//-------------------------------------------------------------------------------------------------------------
//----------------------------------------权限拦截（rbac）-----------------------------------------------------
    public FilterSecurityInterceptor filterSecurityInterceptor(){
        FilterSecurityInterceptor securityInterceptor = new FilterSecurityInterceptor();
        securityInterceptor.setAuthenticationManager(authenticationManager());
        securityInterceptor.setAccessDecisionManager(accessDecisionManager());
        securityInterceptor.setSecurityMetadataSource(myInvocationSecurityMetadataSourceService);
        return securityInterceptor;
    }

    public AffirmativeBased accessDecisionManager(){
        List<AccessDecisionVoter<?>> decisionVoters = new ArrayList<>();
        decisionVoters.add(new RoleVoter());
        AffirmativeBased affirmativeBased = new AffirmativeBased(decisionVoters);
        return affirmativeBased;
    }
//-------------------------------------------------------------------------------------------------------------
}
