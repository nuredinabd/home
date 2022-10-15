module ZuoraAPI
  class Basic < Login
    attr_accessor :username, :password, :session
    def initialize(username: nil, password: nil, session: nil, **keyword_args)
      self.username = username
      self.password = password
      self.current_session = session
      raise ZuoraAPI::Exceptions::ZuoraAPIAuthenticationTypeError.new("Request Basic Login but either 'Username' or 'Password' were not passed.") if self.current_session.blank? && (self.password.blank? && self.username.blank?)
      super
    end

    def new_session(auth_type: :basic, debug: false, zuora_track_id: nil)
      super do 
        raise ZuoraAPI::Exceptions::ZuoraAPIAuthenticationTypeError.new("Basic Login, does not support Authentication of Type: #{auth_type}") if auth_type != :basic
        raise ZuoraAPI::Exceptions::ZuoraAPIAuthenticationTypeError.new("Request Basic Login but either 'Username' or 'Password' were not passed.") if (self.password.blank? && self.username.blank?)

        output_xml, input_xml, response = soap_call(timeout_retry: true, skip_session: true, zuora_track_id: zuora_track_id) do |xml|
          xml['api'].login do
            xml['api'].username self.username
            xml['api'].password self.password
            xml['api'].entityId self.entity_id if !self.entity_id.blank?
          end
        end

        retrieved_session = output_xml.xpath('//ns1:Session', 'ns1' =>'http://api.zuora.com/').text
        raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new("No session found for api call.", response) if retrieved_session.blank?
        self.current_session = retrieved_session
        self.status = 'Active'
        return self.status
      end
    end
  end
end