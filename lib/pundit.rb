require "pundit/version"
require "pundit/policy_finder"
require "active_support/concern"
require "active_support/core_ext/string/inflections"
require "active_support/core_ext/object/blank"
require "active_support/core_ext/module/introspection"
require "active_support/dependencies/autoload"

module Pundit
  SUFFIX = "Policy"

  class Error < StandardError; end
  class NotAuthorizedError < Error
    attr_reader :query, :record, :policy

    def initialize(options = {})
      if options.is_a? String
        message = options
      else
        @query  = options[:query]
        @record = options[:record]
        @policy = options[:policy]

        message = options.fetch(:message) { "not allowed to #{query} this #{record.inspect}" }
      end

      super(message)
    end
  end
  class AuthorizationNotPerformedError < Error; end
  class PolicyScopingNotPerformedError < AuthorizationNotPerformedError; end
  class NotDefinedError < Error; end

  extend ActiveSupport::Concern

  class << self
    def authorize(user, record, query, namespace)
      policy = policy!(user, record, namespace)

      unless policy.public_send(query)
        raise NotAuthorizedError.new(query: query, record: record, policy: policy)
      end

      true
    end

    def policy_scope(user, scope, namespace = Object)
      policy_scope = PolicyFinder.new(scope, namespace).scope
      policy_scope.new(user, scope).resolve if policy_scope
    end

    def policy_scope!(user, scope, namespace = Object)
      PolicyFinder.new(scope, namespace).scope!.new(user, scope).resolve
    end

    def policy(user, record, namespace = Object)
      policy = PolicyFinder.new(record, namespace).policy
      policy.new(user, record) if policy
    end

    def policy!(user, record, namespace = Object)
      PolicyFinder.new(record, namespace).policy!.new(user, record)
    end
  end

  module Helper
    def policy_scope(scope)
      pundit_policy_scope(scope)
    end
  end

  included do
    helper Helper if respond_to?(:helper)
    if respond_to?(:helper_method)
      helper_method :policy
      helper_method :pundit_policy_scope
      helper_method :pundit_user
    end
    if respond_to?(:hide_action)
      hide_action :policy
      hide_action :policy_scope
      hide_action :policies
      hide_action :policy_scopes
      hide_action :authorize
      hide_action :verify_authorized
      hide_action :verify_policy_scoped
      hide_action :permitted_attributes
      hide_action :pundit_user
      hide_action :skip_authorization
      hide_action :skip_policy_scope
      hide_action :pundit_policy_authorized?
      hide_action :pundit_policy_scoped?
    end
  end

  def pundit_policy_authorized?
    !!@_pundit_policy_authorized
  end

  def pundit_policy_scoped?
    !!@_pundit_policy_scoped
  end

  def verify_authorized
    raise AuthorizationNotPerformedError unless pundit_policy_authorized?
  end

  def verify_policy_scoped
    raise PolicyScopingNotPerformedError unless pundit_policy_scoped?
  end

  def authorize(record, namespace = Object, query = nil)
    query ||= params[:action].to_s + "?"

    @_pundit_policy_authorized = true

    policy = policy(record, namespace)
    unless policy.public_send(query)
      raise NotAuthorizedError.new(query: query, record: record, policy: policy)
    end

    true
  end

  def skip_authorization
    @_pundit_policy_authorized = true
  end

  def skip_policy_scope
    @_pundit_policy_scoped = true
  end

  def policy_scope(scope)
    @_pundit_policy_scoped = true
    pundit_policy_scope(scope)
  end

  def policy(record, namespace = Object)
    policies[record] ||= Pundit.policy!(pundit_user, record, namespace)
  end

  def permitted_attributes(record)
    name = record.class.to_s.demodulize.underscore
    params.require(name).permit(*policy(record).permitted_attributes)
  end

  def policies
    @_pundit_policies ||= {}
  end

  def policy_scopes
    @_pundit_policy_scopes ||= {}
  end

  def pundit_user
    current_user
  end

private

  def pundit_policy_scope(scope)
    policy_scopes[scope] ||= Pundit.policy_scope!(pundit_user, scope, self.class.parent)
  end
end
