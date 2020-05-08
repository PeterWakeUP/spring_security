package com.example.springsecuritydemo.config.security.access;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * MOTTO: Rainbow comes after a storm.
 * AUTHOR: sandNul
 * DATE: 2017/6/29
 * TIME: 11:17
 */
@Component
public class MyInvocationSecurityMetadataSourceService implements FilterInvocationSecurityMetadataSource {

    /**
     * 每一个资源所需要的角色
     * (key, value)-->(url, role_list)
     */
    private Map<RequestMatcher, Collection<ConfigAttribute>> map = null;

    @PostConstruct
    public void loadResourceDefine() {
        map = new HashMap<>();

        //权限资源 和 角色对应的表  也就是 角色 权限中间表
        ArrayList<ConfigAttribute> list = new ArrayList<>();
        list.add(new SecurityConfig("admin"));
        map.put(new AntPathRequestMatcher("/system/**"), list);
        //map.put(new AntPathRequestMatcher("/"), list);

        /*List<SysRolePermisson> rolePermissons = sysUserMapper.findAllRolePermissoin();

        //每个资源 所需要的权限
        for (SysRolePermisson rolePermisson : rolePermissons) {
            String url = rolePermisson.getUrl();
            String roleName = rolePermisson.getRoleName();
            ConfigAttribute role = new SecurityConfig(roleName);
            if(map.containsKey(url)){
                map.get(url).add(role);
            }else{
                map.put(url,new ArrayList<ConfigAttribute>(){{
                    add(role);
                }});
            }
        }*/
    }

    /**
     * @param object
     * @return
     * @throws IllegalArgumentException
     */
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        //object 中包含用户请求的request 信息
        HttpServletRequest request = ((FilterInvocation) object).getHttpRequest();
        for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : map.entrySet()) {
            if (entry.getKey().matches(request)) {
                return entry.getValue();
            }
        }
        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributeSet = new HashSet<>();
        for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : map.entrySet()) {
            allAttributeSet.addAll(entry.getValue());
        }
        return allAttributeSet;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}