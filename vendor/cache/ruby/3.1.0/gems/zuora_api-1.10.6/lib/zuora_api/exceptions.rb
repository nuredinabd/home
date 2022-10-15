module ZuoraAPI
  module Exceptions
    class Error < StandardError; 
      def parse_message(message)
        case message
        when /^Payment status should be Processed. Invalid payment is P-\d*./
          @message = "Payment status should be Processed."  
        when /^Adjustment cannot be created for invoice(.*) with a zero balance./
          @message = "Adjustment cannot be created for invoice with a zero balance."
        when /^The balance of all the invoice items and tax items is 0. No write-off is needed for the invoice .*./
          @message = "The balance of all the invoice items and tax items is 0. No write-off is needed for the invoice."
        when /^Json input does not match schema. Error(s): string ".*" is too long .*/
          @message = "Json input does not match schema. Error(s): String is too long."
        when /^Query failed \(#[\d\w_]*\): line [0-9]+:[0-9]+: (.*)$/
          @message = "Query failed: #{$1}"
        when /^Query failed \(#[\d\w_]*\): (.*)$/
          @message = "Query failed: #{$1}"
        when /^Could not find [\w\d]{32}.$/
          @message = "Could not find object."
        when /^Subscription [\w\d]{32} is in expired status. It is not supported to generate billing documents for expired subscriptions./
          @message = "Subscription is in expired status. It is not supported to generate billing documents for expired subscriptions."
        else
          @message = message
        end
      end
    end
    class FileDownloadError < StandardError; end
    class AuthorizationNotPerformed < Error; end
    class ZuoraAPISessionError < Error
      attr_reader :code, :response
      attr_writer :default_message

      def initialize(message = nil,response=nil, errors = [], successes = [])
        @code = response.class.to_s == "HTTParty::Response" ? response.code : nil
        @message = parse_message(message)
        @response = response
        @default_message = "Error with Zuora Session."
      end

      def to_s
        @message || @default_message
      end

      def parse_message(message)
        case message
        when /^Invalid Oauth Client Id$/, /^Unable to generate token.$/
          @message = "Invalid login, please check client ID and Client Secret or URL endpoint"
        when /^Forbidden$/
          @message = "The user associated to OAuth credential set has been deactivated."
        when /^Invalid login. User name and password do not match.$/
          @message = "Invalid login, please check username and password or URL endpoint"
        else
          @message = message
        end
      end
    end

    class BadEntityError < Error
      attr_reader :code, :response, :errors, :successes
      attr_writer :default_message

      def initialize(message = nil,response=nil, errors = [], successes = [],  *args)
        @code = response.class.to_s == "HTTParty::Response" ? response.code : nil
        @message = parse_message(message)
        @response = response
        @default_message = "Error with Zuora Entity"
        @errors = errors
        @successes = successes
      end

      def to_s
        @message || @default_message
      end
    end

    class ZuoraAPIError < Error
      attr_reader :code, :response, :errors, :successes
      attr_writer :default_message

      def initialize(message = nil,response=nil, errors = [], successes = [],  *args)
        @code = response.class.to_s == "HTTParty::Response" ? response.code : nil
        @message = parse_message(message)
        @response = response
        @default_message = "Error communicating with Zuora."
        @errors = errors
        @successes = successes
      end

      def to_s
        @message || @default_message
      end
    end

    class ZuoraAPIInternalServerError < Error
      attr_reader :code, :response, :errors, :successes
      attr_writer :default_message

      def initialize(message = nil,response = nil, errors = [], successes = [], *args)
        @code = response.class.to_s == "HTTParty::Response" ? response.code : nil
        @message = parse_message(message)
        @response = response
        @default_message = "Zuora Internal Server Error."
        @errors = errors
        @successes = successes
      end

      def to_s
        @message || @default_message
      end
    end

    class ZuoraAPIRequestLimit < Error
      attr_reader :code, :response
      attr_writer :default_message

      def initialize(message = nil,response=nil, errors = [], successes = [], *args)
        @code = response.class.to_s == "HTTParty::Response" ? response.code : nil
        @message = parse_message(message)
        @response = response
        @default_message = "Your request limit has been exceeded for zuora."
      end

      def to_s
        @message || @default_message
      end
    end

    class ZuoraAPIUnkownError < Error
      attr_reader :code, :response
      attr_writer :default_message

      def initialize(message = nil,response=nil, errors = [], successes = [], *args)
        @code = response.class.to_s == "HTTParty::Response" ? response.code : nil
        @message = parse_message(message)
        @response = response
        @default_message = "An unkown error occured. Workflow is not responsible. Please contact Support."
      end

      def to_s
        @message || @default_message
      end
    end

    class ZuoraAPILockCompetition < Error
      attr_reader :code, :response
      attr_writer :default_message

      def initialize(message = nil,response=nil, errors = [], successes = [], *args)
        @code = response.class.to_s == "HTTParty::Response" ? response.code : nil
        @message = parse_message(message)
        @response = response
        @default_message = "Operation failed due to lock competition. Please retry"
      end

      def to_s
        @message || @default_message
      end
    end

    class ZuoraDataIntegrity < Error
      attr_reader :code, :response
      attr_writer :default_message

      def initialize(message = nil,response=nil, errors = [], successes = [], *args)
        @code = response.class.to_s == "HTTParty::Response" ? response.code : nil
        @message = parse_message(message)
        @response = response
        @default_message = "Operation failed due to lock competition. Please retry"
      end

      def to_s
        @message || @default_message
      end
    end

    class ZuoraUnexpectedError < Error
      attr_reader :code, :response
      attr_writer :default_message

      def initialize(message = nil, response=nil, errors = [], successes = [], *args)
        @code = response.class.to_s == "HTTParty::Response" ? response.code : nil
        @message = parse_message(message)
        @response = response
        @default_message = "An unexpected error occurred"
      end

      def to_s
        @message || @default_message
      end
    end

    class ZuoraAPITemporaryError < Error
      attr_reader :code, :response, :errors
      attr_writer :default_message

      def initialize(message = nil, response = nil, errors = [], successes = [], *args)
        @code = response.class.to_s == "HTTParty::Response" ? response.code : nil
        @message = parse_message(message)
        @response = response
        @default_message = "There is a temporary error with zuora system."
        @errors = errors
      end

      def to_s
        @message || @default_message
      end
    end    

    class ZuoraAPIAuthenticationTypeError < Error
      attr_reader :code, :response
      attr_writer :default_message

      def initialize(message = nil,response=nil, errors = [], successes = [], *args)
        @code = response.class.to_s == "HTTParty::Response" ? response.code : nil
        @message = parse_message(message)
        @response = response
        @default_message = "Authentication type is not supported by this Login"
      end

      def to_s
        @message || @default_message
      end
    end

    class ZuoraAPIConnectionTimeout < Net::OpenTimeout
      attr_reader :code, :response
      attr_writer :default_message

      def initialize(message = nil,response=nil, errors = [], successes = [], *args)
        @code = response.class.to_s == "HTTParty::Response" ? response.code : nil
        @message = message
        @response = response
        @default_message = "Authentication type is not supported by this Login"
      end

      def to_s
        @message || @default_message
      end
    end

    class ZuoraAPIReadTimeout < Timeout::Error
      attr_reader :code, :response, :request
      attr_writer :default_message

      def initialize(message = nil, response = nil, request = nil, errors = [], successes = [], *args)
        @code = response.class.to_s == "HTTParty::Response" ? response.code : nil
        @message = message
        @response = response
        @request = request
        @default_message = "Authentication type is not supported by this Login"
      end

      def to_s
        @message || @default_message
      end
    end
  end
end
