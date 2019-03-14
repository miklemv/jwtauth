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
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;


public abstract class BaseUrlAuthenticationFilter extends GenericFilterBean {

    private List<String> urlPatterns;
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public BaseUrlAuthenticationFilter(String urlPattern) {
        this.urlPatterns = Collections.singletonList(urlPattern);
    }
    public BaseUrlAuthenticationFilter(List<String> urlPatterns) {
        this.urlPatterns = urlPatterns;
    }

    public List<String> getUrlPatterns() {
        return urlPatterns;
    }

    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        if (request instanceof HttpServletRequest) {
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                String uri = ((HttpServletRequest) request).getRequestURI().toString();
                for (String urlPattern : urlPatterns) {
                    if (Pattern.matches(urlPattern, uri)) {
                        Authentication authentication = authentication(request, response);
                        if (authentication != null) {
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                        }
                        break;
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
