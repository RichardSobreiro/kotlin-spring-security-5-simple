package br.com.cbauthserver.authserverconfig

import br.com.cbauthserver.jwks.KeyGeneratorUtils
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcTemplate
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
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.oauth2.server.authorization.config.TokenSettings
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import java.time.Duration
import java.util.*

import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository

@Configuration(proxyBeanMethods = false)
class AuthorizationServerConfig(
    @Autowired
    val jdbcTemplate: JdbcTemplate
) {
    private val issuerUrl = "http://localhost:8080"

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http.cors().and())

        http.cors().and().csrf().disable()
            .formLogin(withDefaults<FormLoginConfigurer<HttpSecurity>>())

        return http.build()
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
    fun registeredClientRepository(
        passwordEncoder: BCryptPasswordEncoder
    ): RegisteredClientRepository {
        val registeredClientRepository = JdbcRegisteredClientRepository(jdbcTemplate)
        val registeredClientParametersMapper = JdbcRegisteredClientRepository.RegisteredClientParametersMapper()
        val yourClientId = "yourClientId"
        val yourSecret = "yourSecret"

        registeredClientParametersMapper.setPasswordEncoder(passwordEncoder)
        registeredClientRepository.setRegisteredClientParametersMapper(registeredClientParametersMapper)

        if (registeredClientRepository.findByClientId(yourClientId) == null) {
            val registeredClient: RegisteredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .tokenSettings(
                    TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(5))
                        .refreshTokenTimeToLive(Duration.ofMinutes(10))
                        .build()
                )
                .clientId(yourClientId)
                .clientSecret(yourSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8081/authorized")
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scope(OidcScopes.OPENID)
                .scope("")
                .scope("yourapplication.read")
                .scope("yourapplication.write")
                .build()

            registeredClientRepository.save(registeredClient)
        }

        return registeredClientRepository
    }

    @Bean
    fun authorizationService(
        registeredClientRepository: RegisteredClientRepository
    ): OAuth2AuthorizationService {
        return JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)
    }

    @Bean
    fun users(): UserDetailsService {
        val user = User.builder()
            .username("pele")
            .password("{bcrypt}\$2a\$10\$b.Rm.8NeuT7hS3Qwy1RPGuuHNMzjEk01vM7ExvW/h11KAHainYBfK")
            .roles("USER")
            .build()
        val admin = User.builder()
            .username("garrincha")
            .password("{bcrypt}\$2a\$10\$b.Rm.8NeuT7hS3Qwy1RPGuuHNMzjEk01vM7ExvW/h11KAHainYBfK")
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