package br.com.cbauthserver.authserverconfig

import br.com.cbauthserver.jwks.KeyGeneratorUtils
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.oauth2.server.authorization.config.TokenSettings
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import java.time.Duration
import java.util.*

import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository

@Configuration(proxyBeanMethods = false)
class AuthorizationServerConfig(
) {
    private val issuerUrl = "http://auth-server:9000"
    private val yourClientId = "yourClientId"
    private val yourSecret = "yourSecret"

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(Customizer.withDefaults()).build();
        /*OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(
            http.cors().and().csrf().disable().formLogin(Customizer.withDefaults()))*/

        /*http.cors().and().csrf().disable()
            .formLogin(withDefaults<FormLoginConfigurer<HttpSecurity>>())*/

        return http.build()
    }

    @Bean
    fun registeredClientRepository (): RegisteredClientRepository  {
        val registeredClient: RegisteredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(yourClientId)
            .clientSecret(passwordEncoder().encode("yourSecret"))
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
            .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
            .scope(OidcScopes.OPENID)
            //.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
            .build()

        /*val registeredClient: RegisteredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .tokenSettings(
                TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMinutes(5))
                    .refreshTokenTimeToLive(Duration.ofMinutes(10))
                    .build()
            )
            .clientId(yourClientId)
            .clientSecret(passwordEncoder().encode("yourSecret"))
            //.clientSecret("yourSecret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
            .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
            .scope(OidcScopes.OPENID)
            //.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
            .build()*/

        return InMemoryRegisteredClientRepository(listOf(registeredClient))
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val rsaKey = KeyGeneratorUtils.generateRSAKey()
        val jwkSet = JWKSet(rsaKey)
        return JWKSource<SecurityContext> { jwkSelector, _ -> jwkSelector.select(jwkSet) }
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }

    @Bean
    fun providerSettings(): ProviderSettings {
        return ProviderSettings.builder().issuer(issuerUrl).build()
    }

    @Bean
    fun passwordEncoder() = BCryptPasswordEncoder(10)

    @Bean
    fun users(): UserDetailsService {
        val user = User.builder()
            .username("pele")
            .password("\$2a\$10\$b.Rm.8NeuT7hS3Qwy1RPGuuHNMzjEk01vM7ExvW/h11KAHainYBfK")
            //.password("123456")
            .roles("USER")
            .build()
        val admin = User.builder()
            .username("garrincha")
            .password("\$2a\$10\$b.Rm.8NeuT7hS3Qwy1RPGuuHNMzjEk01vM7ExvW/h11KAHainYBfK")
            //.password("123456")
            .roles("USER", "ADMIN")
            .build()
        return InMemoryUserDetailsManager(user, admin)
    }

    /*@Bean
    fun clientRegistrationRepository(): ClientRegistrationRepository {
        return InMemoryClientRegistrationRepository(simpleClientRegistration())
    }

    private fun simpleClientRegistration(): ClientRegistration {
        return ClientRegistration
            .withRegistrationId("simple")
            .clientId("google-client-id")
            .clientSecret("google-client-secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8081/client")
            .scope("openid")
            .authorizationUri("http://localhost:8080/authorize")
            .tokenUri("http://localhost:8080/token")
            .build()
    }*/

}