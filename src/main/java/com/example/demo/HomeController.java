package com.example.demo;

// Importações necessárias para o funcionamento do controlador e SAML
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller  
public class HomeController {

    @RequestMapping("/")  
    public String home(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
        // Adiciona o nome do usuário autenticado ao modelo
        model.addAttribute("name", principal.getName());

        // Tenta obter o e-mail do usuário a partir dos atributos fornecidos
        String email = principal.getFirstAttribute("email");
        if (email == null) {
            email = principal.getFirstAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
        }

        // Adiciona o email e os atributos do usuário ao modelo para serem exibidos na página
        model.addAttribute("emailAddress", email);
        model.addAttribute("userAttributes", principal.getAttributes());

        // Retorna o nome da página que será renderizada (home.html)
        return "home";
    }
}
