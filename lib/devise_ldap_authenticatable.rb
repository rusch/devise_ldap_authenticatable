# encoding: utf-8
require 'devise'

require 'devise_ldap_authenticatable/exception'
require 'devise_ldap_authenticatable/logger'
require 'devise_ldap_authenticatable/ldap/adapter'
require 'devise_ldap_authenticatable/ldap/connection'
require 'pathname'

# Get ldap information from config/ldap.yml now
module Devise
  # Allow logging
  mattr_accessor :ldap_logger
  @@ldap_logger = true
  
  # Add valid users to database
  mattr_accessor :ldap_create_user
  @@ldap_create_user = false
  
  # A path to YAML config file or a Proc that returns a
  # configuration hash
  mattr_reader :ldap_config_path
  if defined?(Rails) && Rails.root.is_a?(Pathname)
    @@ldap_config_path = Rails.root + 'config/ldap.yml'
  end

  def self.ldap_config_path=(path)
    if defined?(@@ldap_config)
      remove_class_variable(:@@ldap_config)
    end
    @@ldap_config_path = Pathname.new(path)
  end
  
  mattr_accessor :ldap_update_password
  @@ldap_update_password = true
  
  mattr_accessor :ldap_check_group_membership
  @@ldap_check_group_membership = false
  
  mattr_accessor :ldap_check_attributes
  @@ldap_check_role_attribute = false
  
  mattr_accessor :ldap_use_admin_to_bind
  @@ldap_use_admin_to_bind = false
  
  mattr_accessor :ldap_check_group_membership_without_admin
  @@ldap_check_group_membership_without_admin = false

  mattr_accessor :ldap_auth_username_builder
  @@ldap_auth_username_builder = Proc.new() {|attribute, login, ldap| "#{attribute}=#{login},#{ldap.base}" }

  def self.ldap_config
    if defined?(@@ldap_config)
      if @@ldap_config.is_a?(Proc)
        return post_process_config(@@ldap_config.call)
      end
      return @@ldap_config
    end

    @@ldap_config = post_process_config(
      YAML.load(ERB.new(ldap_config_path.read).result)[Rails.env]
    )
  end

  def self.ldap_config=(value)
    case value
    when Hash, Proc
      @@ldap_config = value
      if defined?(@@ldap_config_path)
        remove_class_variable(:@@ldap_config_path)
      end

    # Preserve compatibiltiy.
    when Pathname, String
      self.ldap_config_path = value
    else
      raise ArgumentError, 'ldap_config must be either Hash, Proc, String or Pathname.'
    end
  end

  mattr_accessor :ldap_auth_password_builder
  @@ldap_auth_password_builder = Proc.new() do |new_password|
    Net::LDAP::Password.generate(::Devise.ldap_config['password_hash_algo'], new_password)
  end

  mattr_accessor :ldap_ad_group_check
  @@ldap_ad_group_check = false

  private

    def self.post_process_config(cfg)
    cfg["ssl"] = :simple_tls if cfg["ssl"] === true

    # password hash algorithm. the .generate call is used for checking if the
    # selected method is supported by Net::LDAP.  It raises an
    # Net::LDAP::HashTypeUnsupportedError exception when the method
    # is not supported.
    if cfg.key?('password_hash_algo')
      cfg['password_hash_algo'] = cfg['password_hash_algo'].to_s.to_sym
      Net::LDAP::Password.generate(cfg['password_hash_algo'], "")
    else
      cfg['password_hash'] = :ssha
    end

    cfg
  end

end

# Add ldap_authenticatable strategy to defaults.
#
Devise.add_module(:ldap_authenticatable,
                  :route => :session, ## This will add the routes, rather than in the routes.rb
                  :strategy   => true,
                  :controller => :sessions,
                  :model  => 'devise_ldap_authenticatable/model')
