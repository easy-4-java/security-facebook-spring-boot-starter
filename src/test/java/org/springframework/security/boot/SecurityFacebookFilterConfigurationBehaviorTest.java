package org.springframework.security.boot;

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.OkHttpClient;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.extension.web.servlet.i18n.LocaleContextFilter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.facebook.authentication.FacebookAccessTokenAuthenticationProcessingFilter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;

class SecurityFacebookFilterConfigurationBehaviorTest {

    @Test
    void createsConfiguredFacebookAuthenticationFilter() throws Exception {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("objectMapper", new ObjectMapper());
        beans.addBean("okHttpClient", new OkHttpClient());
        beans.addBean("authenticationProvider", mock(AuthenticationProvider.class));

        SecurityFacebookFilterConfiguration.FacebookWebSecurityCustomizerAdapter adapter =
                new SecurityFacebookFilterConfiguration.FacebookWebSecurityCustomizerAdapter(
                        new SecurityBizProperties(),
                        new SecuritySessionMgtProperties(),
                        new SecurityFacebookAuthcProperties(),
                        beans.getBeanProvider(AccessDeniedHandler.class),
                        beans.getBeanProvider(LocaleContextFilter.class),
                        beans.getBeanProvider(AuthenticationProvider.class),
                        beans.getBeanProvider(AuthenticationListener.class),
                        beans.getBeanProvider(MatchedAuthenticationEntryPoint.class),
                        beans.getBeanProvider(MatchedAuthenticationSuccessHandler.class),
                        beans.getBeanProvider(MatchedAuthenticationFailureHandler.class),
                        beans.getBeanProvider(ObjectMapper.class),
                        beans.getBeanProvider(OkHttpClient.class),
                        beans.getBeanProvider(RememberMeServices.class),
                        beans.getBeanProvider(SessionAuthenticationStrategy.class));

        FacebookAccessTokenAuthenticationProcessingFilter filter = adapter.authenticationProcessingFilter();
        assertNotNull(filter);
    }
}
