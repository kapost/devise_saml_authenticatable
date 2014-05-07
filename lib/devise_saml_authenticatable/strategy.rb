require 'devise/strategies/authenticatable' 
module Devise
  module Strategies
    class SamlAuthenticatable < Authenticatable
      include DeviseSamlAuthenticatable::SamlConfig
      def valid?
        params[:SAMLResponse]
      end
      def authenticate!
        @response = OneLogin::RubySaml::Response.new(params[:SAMLResponse])

        settings = get_saml_config

        sub = Subdomain.first(request)
        umbrella = Newsroom.find_by(:subdomain => sub)

        settings.idp_sso_target_url = umbrella.saml_issuer_url
        settings.idp_cert = umbrella.secret_sso_x509_cert.decrypt

        @response.settings = settings
	      resource = mapping.to.authenticate_with_saml(@response.attributes)
        if @response.is_valid?
          success!(resource)
        else
          fail!(:invalid)
        end
      end
      
      # This method should turn off storage whenever CSRF cannot be verified.
      # Any known way on how to let the IdP send the CSRF token along with the SAMLResponse ?
      # Please let me know!
      def store?
        true
      end
            
    end
  end
end

Warden::Strategies.add(:saml_authenticatable, Devise::Strategies::SamlAuthenticatable)
