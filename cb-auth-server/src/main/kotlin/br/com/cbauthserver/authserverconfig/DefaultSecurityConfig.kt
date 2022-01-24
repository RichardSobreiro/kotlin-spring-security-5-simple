package br.com.cbauthserver.authserverconfig

import org.springframework.context.annotation.Bean
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain


@EnableWebSecurity(debug = true)
class DefaultSecurityConfig {
    @Bean
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        /*http.cors().and().csrf().disable()
            .authorizeRequests { authorizeRequests -> authorizeRequests.anyRequest().authenticated() }
            .formLogin(Customizer.withDefaults())*/

        /*http
            .authorizeRequests { authorizeRequests -> authorizeRequests.anyRequest().authenticated() }
            .formLogin(withDefaults())*/
        http
            .authorizeRequests { authorizeRequests -> authorizeRequests.anyRequest().authenticated() }
            .formLogin(withDefaults())
        return http.build()
    }
}

    /*@Bean
    protected fun corsConfigurationSource(): CorsConfigurationSource {
        val source = UrlBasedCorsConfigurationSource()
        val corsConfig = CorsConfiguration().applyPermitDefaultValues().apply {
            allowedOrigins = listOf("*")
            allowCredentials = true
            allowedHeaders = listOf("*")
            allowedMethods = listOf("GET", "POST", "PUT", "OPTIONS", "DELETE", "PATCH")
        }
        source.registerCorsConfiguration("/**", corsConfig)
        return source
    }*/