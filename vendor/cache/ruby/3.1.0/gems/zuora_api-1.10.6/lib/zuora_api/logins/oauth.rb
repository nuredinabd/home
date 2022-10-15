module ZuoraAPI
  class Oauth < Login
    attr_accessor :oauth_client_id, :oauth_secret, :bearer_token, :oauth_session_expires_at, :scope_entities
    
    def initialize(oauth_client_id: nil, oauth_secret: nil, bearer_token: nil, oauth_session_expires_at: nil, **keyword_args)
      self.oauth_client_id = oauth_client_id
      self.oauth_secret = oauth_secret
      self.bearer_token = bearer_token
      self.oauth_session_expires_at = oauth_session_expires_at
      raise ZuoraAPI::Exceptions::ZuoraAPIAuthenticationTypeError.new("Request Oauth Login but either 'Oauth Client Id' or 'Oauth Secret' were not passed") if self.bearer_token.blank? && (self.oauth_client_id.blank? || self.oauth_secret.blank?)
      super
    end

    def new_session(auth_type: nil, zuora_track_id: nil)
      super do
        if auth_type ==  :bearer
          get_bearer_token(zuora_track_id: zuora_track_id)
        elsif auth_type == :basic
          get_bearer_token(zuora_track_id: zuora_track_id) if self.oauth_expired?
          get_z_session(zuora_track_id: zuora_track_id)
        else
          get_bearer_token(zuora_track_id: zuora_track_id) if self.oauth_expired?
          get_z_session(zuora_track_id: zuora_track_id) 
        end
        return self.status
      end
    end

    def get_active_bearer_token
      self.get_bearer_token if self.oauth_expired?
      return self.bearer_token
    end
    
    def get_z_session(debug: false, zuora_track_id: nil)
      headers = self.entity_header
      headers['Zuora-Track-Id'] = zuora_track_id if zuora_track_id.present?
      headers['X-Amzn-Trace-Id'] = zuora_track_id if zuora_track_id.present?
      output_json, response = self.rest_call(:url => self.rest_endpoint("connections"), :session_type => :bearer, :headers => headers)
      begin
        self.current_session = response.headers.to_h['set-cookie'][0].split(';')[0].split('=',2)[1].gsub('%3D', '=')
      rescue NoMethodError => ex 
        Rails.logger.fatal("Failure Parsing Cookie Headers", {
          response: {
            status: response.code,
            params: response.body.to_s,
            headers: response.headers.to_s,
          }
        })
        raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new("Failure Parsing Cookie Headers", response)
      end 
    end

    def get_bearer_token(zuora_track_id: nil)
      raise ZuoraAPI::Exceptions::ZuoraAPIAuthenticationTypeError.new("Request Oauth Login but either 'Oauth Client Id' or 'Oauth Secret' were not passed") if self.oauth_client_id.blank? || self.oauth_secret.blank?

      headers = { "content-type" => "application/x-www-form-urlencoded" }
      headers['Zuora-Track-Id'] = zuora_track_id if zuora_track_id.present?
      headers['X-Amzn-Trace-Id'] = zuora_track_id if zuora_track_id.present?

      output_json, response = self.rest_call(:method => :post, 
        url: self.rest_endpoint.chomp('v1/').concat("oauth/token"), 
        z_session: false,
        timeout_retry: true,
        headers: headers,
        body: {"client_id"=> self.oauth_client_id, "client_secret"=>self.oauth_secret, "grant_type" =>"client_credentials"}
      )

      self.bearer_token = output_json["access_token"]
      self.scope_entities = output_json.fetch('scope', '').split(" ").map { |scope| scope.split('.').last.gsub('-', '') if scope.include?('entity.') }.compact.uniq
      self.oauth_session_expires_at = Time.now.to_i + output_json["expires_in"].to_i
      self.current_error = nil
      self.status = 'Active'

      return self.status
    end

    def oauth_expired?
      return (self.oauth_session_expires_at.blank? || self.bearer_token.blank?) ? true : (self.oauth_session_expires_at.to_i < Time.now.to_i)
    end
  end
end