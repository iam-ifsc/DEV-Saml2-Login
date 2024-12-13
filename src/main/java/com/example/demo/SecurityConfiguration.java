package com.example.demo;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider.ResponseToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration 
public class SecurityConfiguration {

    @Bean
    SecurityFilterChain configure(HttpSecurity http) throws Exception {
 
        http.authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()) // Todas as requisições devem ser autenticadas
            .saml2Login(saml2 -> saml2
                .authenticationManager(new ProviderManager(createAuthenticationProvider()))) // Configura o login SAML2 com um AuthenticationManager personalizado
            .saml2Logout(withDefaults()); // Configura o logout SAML2 com padrões

        return http.build(); // Constrói a configuração
    }

    // Cria um provedor de autenticação SAML2  
    private OpenSaml4AuthenticationProvider createAuthenticationProvider() {
        OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(groupsConverter());
        return authenticationProvider;
    }

    // Define um conversor para atribuir grupos de usuários como autoridades
    private Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> groupsConverter() {
        Converter<ResponseToken, Saml2Authentication> delegate =
            OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter(); // Conversor padrão

        // Adiciona grupos como autoridades
        return (responseToken) -> {
            Saml2Authentication authentication = delegate.convert(responseToken); // Converte o token de resposta SAML2
            Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
            List<String> groups = principal.getAttribute("groups"); // Obtém grupos do atributo "groups"
            Set<GrantedAuthority> authorities = new HashSet<>();

            // Fallback (é acionada quando a abordagem principal falha) para um namespace alternativo de atributo de grupos
            if (groups == null) {
                groups = principal.getAttribute("http://schemas.auth0.com/roles");
            }

            // Adiciona cada grupo como uma autoridade com o prefixo "ROLE_"
            if (groups != null) {
                groups.forEach(group -> authorities.add(new SimpleGrantedAuthority("ROLE_" + group)));
            }

            // Retorna a autenticação SAML2 com as autoridades adicionadas
            return new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);
        };
    }
}
