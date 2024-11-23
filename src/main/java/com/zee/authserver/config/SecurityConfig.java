package com.zee.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import static org.springframework.core.Ordered.HIGHEST_PRECEDENCE;

/**
 * @author : Ezekiel Eromosei
 * @code @created : 18 Sep, 2024
 */

@Configuration
public class SecurityConfig {
    public static final String AUTHORITIES = "authorities";

    @Bean
    @Order(HIGHEST_PRECEDENCE)
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);

        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        httpSecurity.exceptionHandling(
                e -> e.authenticationEntryPoint(
                        new LoginUrlAuthenticationEntryPoint("/login")
                )
        );

        return httpSecurity.build();
    }

    @Bean
    @Order(HIGHEST_PRECEDENCE + 1)
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception { // app filter chain
        http.formLogin(Customizer.withDefaults())
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/login")
                        .permitAll()
                        .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        var uds = User.withUsername("user")
                .password("password")
                .authorities("create", "read", "update", "delete")
                .build();

        return new InMemoryUserDetailsManager(uds);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(){

        RegisteredClient r1 = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientSecret("secret")
                .scopes(scs -> scs.addAll(List.of(OidcScopes.OPENID, OidcScopes.PROFILE)))
                .redirectUri("https://springone.io/authorized")
                .clientAuthenticationMethods(authMethods -> {
                    authMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                })
                .authorizationGrantTypes(grantTypes -> {
                    grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    grantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
                })
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(24))
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .authorizationCodeTimeToLive(Duration.ofMinutes(10))
                        .setting(AUTHORITIES, List.of("create", "read", "update", "delete"))
                        .build())
                .build();
        return new InMemoryRegisteredClientRepository(r1);
    }



    @Bean
    public AuthorizationServerSettings authorizationServerSettings(){
        return AuthorizationServerSettings.builder().build(); // Oauth urls
    }


    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
        return context -> {
            context.getClaims()
                    .claim("test", "test")
                    .claim("user_name", StringUtils.hasText(context.getPrincipal().getName()) ? context.getPrincipal().getName() : "");

            Collection<? extends GrantedAuthority> grantedAuthorities = context.getPrincipal().getAuthorities();// GrantedAuthority

            context.getClaims().claim(AUTHORITIES, grantedAuthorities.stream().map(GrantedAuthority::getAuthority).toList()); //List<String

            if (context.getAuthorizationGrantType().getValue().equals(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())) {
                List<String> authorities = context.getRegisteredClient().getTokenSettings().getSetting(AUTHORITIES);
                context.getClaims().claim(AUTHORITIES, authorities);
            }
        };
    }


}
