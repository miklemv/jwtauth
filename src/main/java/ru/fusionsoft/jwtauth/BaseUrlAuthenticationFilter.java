package ru.fusionsoft.jwtauth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.regex.Pattern;


public abstract class BaseUrlAuthenticationFilter extends GenericFilterBean {

    private String urlPattern;
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public BaseUrlAuthenticationFilter(String urlPattern) {
        this.urlPattern = urlPattern;
    }

    public String getUrlPattern() {
        return urlPattern;
    }

    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        if (request instanceof HttpServletRequest) {
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                String uri = ((HttpServletRequest) request).getRequestURI().toString();
                if (Pattern.matches(urlPattern, uri)) {

                    Authentication authentication = authentication(request, response);
                    if (authentication != null) {
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            }
        }

        chain.doFilter(request, response);
    }

    public Logger getLogger() {
        return logger;
    }

    public abstract Authentication authentication(ServletRequest request, ServletResponse response);
}
