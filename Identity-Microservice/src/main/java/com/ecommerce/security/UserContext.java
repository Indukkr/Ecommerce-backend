package com.ecommerce.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public final class UserContext {

    private UserContext(){

    }

    public static String getUserEmail(){
        Authentication authentication=SecurityContextHolder
                .getContext().getAuthentication();
        if(authentication==null || !authentication.isAuthenticated()){
            return null;
        }
        return authentication.getName();
    }
}
