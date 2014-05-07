require "ruby-saml"

class Devise::SamlSessionsController < Devise::SessionsController
  include DeviseSamlAuthenticatable::SamlConfig
  unloadable if Rails::VERSION::MAJOR < 4
  before_filter :load_saml_config
  def new
    request = OneLogin::RubySaml::Authrequest.new
    action = request.create(@saml_config)
    redirect_to action
  end
      
  def metadata
    meta = OneLogin::RubySaml::Metadata.new
    render :xml => meta.generate(@saml_config)
  end

  def load_saml_config
    get_saml_config

    @saml_config.idp_sso_target_url = context.umbrella.saml_issuer_url
    @saml_config.idp_cert = context.umbrella.secret_sso_x509_cert.decrypt
  end

end

