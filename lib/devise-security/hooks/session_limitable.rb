# frozen_string_literal: true

# After each sign in, update unique_session_id.
# This is only triggered when the user is explicitly set (with set_user)
# and on authentication. Retrieving the user from session (:fetch) does
# not trigger it.

# With patch from https://github.com/devise-security/devise-security/pull/79
# made by Mister https://github.com/kirichkov

Warden::Manager.after_set_user except: :fetch do |record, warden, options|
  scope = options[:scope]
  skip  = options[:skip_session_limitable]

  if record.respond_to?(:update_unique_session_id!) && warden.authenticated?(options[:scope]) 
    if !skip
      unique_session_id = Devise.friendly_token
      warden.session(scope)['unique_session_id'] = unique_session_id
      record.update_unique_session_id!(unique_session_id)
    else
      warden.session(scope)['devise.skip_session_limitable'] = true
    end
  end
end

# Each time a record is fetched from session we check if a new session from another
# browser was opened for the record or not, based on a unique session identifier.
# If so, the old account is logged out and redirected to the sign in page on the next request.
Warden::Manager.after_set_user only: :fetch do |record, warden, options|
  scope = options[:scope]
  skip  = warden.session(options[:scope])['devise.skip_session_limitable']

  if record.respond_to?(:unique_session_id) && warden.authenticated?(scope) && options[:store] != false
    if record.unique_session_id != warden.session(scope)['unique_session_id'] && !skip
      warden.raw_session.clear
      warden.logout(scope)
      throw :warden, scope: scope, message: :session_limited
    end
  end
end