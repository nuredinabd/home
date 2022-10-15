require "httparty"
require "nokogiri"
require "uri"
require 'zuora_api/exceptions'

module ZuoraAPI
  class Login
    ENVIRONMENTS = [TEST = 'Test', SANDBOX = 'Sandbox', PRODUCTION = 'Production', PREFORMANCE = 'Preformance', SERVICES = 'Services', UNKNOWN = 'Unknown', STAGING = 'Staging' ]
    REGIONS = [EU = 'EU', US = 'US', NA = 'NA' ]
    MIN_Endpoints = {'Test': '115.0', 'Sandbox': '115.0', 'Production': '115.0', 'Performance': '115.0', 'Services': '96.0', 'Unknown': '96.0', 'Staging': '115.0'}.freeze
    XML_SAVE_OPTIONS = Nokogiri::XML::Node::SaveOptions::AS_XML | Nokogiri::XML::Node::SaveOptions::NO_DECLARATION
    USER_AGENT = "Zuora#{ENV['Z_APPLICATION_NAME']&.capitalize}/#{ENV['Z_APPLICATION_VERSION']&.delete('v')}"

    CONNECTION_EXCEPTIONS = [
      Net::OpenTimeout,
      OpenSSL::SSL::SSLError,
      Errno::ECONNREFUSED,
      SocketError,
      Errno::EHOSTUNREACH,
      Errno::EADDRNOTAVAIL,
      Errno::ETIMEDOUT,
    ].freeze

    CONNECTION_READ_EXCEPTIONS = [
      Timeout::Error,
      Errno::ECONNRESET,
      Errno::EPIPE
    ].freeze

    ZUORA_API_ERRORS = [
      ZuoraAPI::Exceptions::ZuoraAPIError,
      ZuoraAPI::Exceptions::ZuoraAPIRequestLimit,
      ZuoraAPI::Exceptions::ZuoraAPILockCompetition,
      ZuoraAPI::Exceptions::ZuoraAPITemporaryError,
      ZuoraAPI::Exceptions::ZuoraDataIntegrity,
      ZuoraAPI::Exceptions::ZuoraAPIInternalServerError,
      ZuoraAPI::Exceptions::ZuoraUnexpectedError,
      ZuoraAPI::Exceptions::ZuoraAPIUnkownError
    ].freeze

    ZUORA_SERVER_ERRORS = [
      ZuoraAPI::Exceptions::ZuoraAPIInternalServerError,
        ZuoraAPI::Exceptions::ZuoraAPIConnectionTimeout,
        ZuoraAPI::Exceptions::ZuoraAPIReadTimeout,
      ZuoraAPI::Exceptions::ZuoraUnexpectedError
    ].freeze

    attr_accessor :region, :url, :wsdl_number, :current_session, :bearer_token, :oauth_session_expires_at, :environment, :status, :errors, :current_error, :user_info, :tenant_id, :tenant_name, :entity_id, :entity_identifier, :entity_header_type, :timeout_sleep, :hostname, :zconnect_provider

    def initialize(url: nil, entity_id: nil, entity_identifier: nil, session: nil, status: nil, bearer_token: nil, oauth_session_expires_at: nil, **keyword_args)
      raise "URL is nil or empty, but URL is required" if url.nil? || url.empty?
      # raise "URL is improper. URL must contain zuora.com, zuora.eu, or zuora.na" if /zuora.com|zuora.eu|zuora.na/ === url
      self.hostname = /(?<=https:\/\/|http:\/\/)(.*?)(?=\/|$)/.match(url)[0] if !/(?<=https:\/\/|http:\/\/)(.*?)(?=\/|$)/.match(url).nil?
      self.update_environment
      min_endpoint = MIN_Endpoints[self.environment.to_sym]
      if !/apps\/services\/a\/\d+\.\d$/.match(url.strip)
        self.url = "https://#{hostname}/apps/services/a/#{min_endpoint}"
      elsif min_endpoint.to_f > url.scan(/(\d+\.\d)$/).dig(0,0).to_f
        self.url = url.gsub(/(\d+\.\d)$/, min_endpoint)
      else
        self.url = url
      end
      self.entity_id = get_entity_id(entity_id: entity_id)
      self.entity_identifier = entity_identifier
      self.entity_header_type = :entity_id
      self.errors = Hash.new
      self.current_session = session
      self.bearer_token = bearer_token
      self.oauth_session_expires_at = oauth_session_expires_at
      self.status = status.blank? ? "Active" : status
      self.user_info = Hash.new
      self.update_region
      self.update_zconnect_provider
      @timeout_sleep = 5
    end

    def get_identity(cookies)
      zsession = cookies["ZSession"]
      begin
        if !zsession.blank?
          response = HTTParty.get("https://#{self.hostname}/apps/v1/identity", :headers => {'Cookie' => "ZSession=#{zsession}", 'Content-Type' => 'application/json', "User-Agent" => USER_AGENT})
          output_json = JSON.parse(response.body)
        else
          raise ZuoraAPI::Exceptions::ZuoraAPIError.new("No ZSession cookie present")
        end
      rescue JSON::ParserError => ex
        output_json = {}
      end
      raise_errors(type: :JSON, body: output_json, response: response)
      return output_json
    end

    def get_full_nav(cookies)
      zsession = cookies["ZSession"]
      begin
        if zsession.present?
          response = HTTParty.get("https://#{self.hostname}/apps/v1/navigation", :headers => {'Cookie' => "ZSession=#{zsession}", 'Content-Type' => 'application/json', "User-Agent" => USER_AGENT})
          output_json = JSON.parse(response.body)
        else
          raise ZuoraAPI::Exceptions::ZuoraAPIError.new("No ZSession cookie present")
        end
      rescue JSON::ParserError => ex
        output_json = {}
      end
      raise_errors(type: :JSON, body: output_json, response: response)
      return output_json
    end

    def set_nav(state, cookies)
      zsession = cookies["ZSession"]
      begin
        if !zsession.blank?
          response = HTTParty.put("https://#{self.hostname}/apps/v1/preference/navigation", :body => state.to_json, :headers => {'Cookie' => "ZSession=#{zsession}", 'Content-Type' => 'application/json', "User-Agent" => USER_AGENT})
          output_json = JSON.parse(response.body)
        else
          raise ZuoraAPI::Exceptions::ZuoraAPIError.new("No ZSession cookie present")
        end
      rescue JSON::ParserError => ex
        output_json = {}
      end
      raise_errors(type: :JSON, body: output_json, response: response)
      return output_json
    end

    def refresh_nav(cookies)
      zsession = cookies["ZSession"]
      begin
        if !zsession.blank?
          response = HTTParty.post("https://#{self.hostname}/apps/v1/navigation/fetch", :headers => {'Cookie' => "ZSession=#{zsession}", 'Content-Type' => 'application/json', "User-Agent" => USER_AGENT})
          output_json = JSON.parse(response.body)
        else
          raise ZuoraAPI::Exceptions::ZuoraAPIError.new("No ZSession cookie present")
        end
      rescue JSON::ParserError => ex
        output_json = {}
      end
      raise_errors(type: :JSON, body: output_json, response: response)
      return output_json
    end

    def reporting_url(path)
      map = {"US" => {"Sandbox" => "https://zconnectsandbox.zuora.com/api/rest/v1/",
                      "Production" => "https://zconnect.zuora.com/api/rest/v1/",
                      "Test" => "https://zconnect-services0001.test.zuora.com/api/rest/v1/",
                      "Staging" => "https://reporting-stg11.zan.svc.auw2.zuora.com/api/rest/v1/",
                      "Performance" => "https://zconnectpt1.zuora.com/api/rest/v1/",
                      "Services" => "https://reporting-svc08.svc.auw2.zuora.com/api/rest/v1/"},
             "EU" => {"Sandbox" => "https://zconnect.sandbox.eu.zuora.com/api/rest/v1/",
                      "Production" => "https://zconnect.eu.zuora.com/api/rest/v1/",
                      "Services"=> "https://reporting-sbx0000.sbx.aec1.zuora.com/api/rest/v1/",
                      "Test" => "https://zconnect-services0002.test.eu.zuora.com/api/rest/v1/"},
             "NA" => {"Sandbox" => "https://zconnect.sandbox.na.zuora.com/api/rest/v1/",
                      "Production" => "https://zconnect.na.zuora.com/api/rest/v1/",
                      "Services"=> ""}
      }
      return map[self.region][self.environment].insert(-1, path)
    end

    # There are two ways to call this method. The first way is best.
    # 1. Pass in cookies and optionally custom_authorities, name, and description
    # 2. Pass in user_id, entity_ids, client_id, client_secret, and optionally custom_authorities, name, and description
    # https://intranet.zuora.com/confluence/display/Sunburst/Create+an+OAuth+Client+through+API+Gateway#CreateanOAuthClientthroughAPIGateway-ZSession
    def get_oauth_client (custom_authorities = [], info_name: "No Name", info_desc: "This client was created without a description.", user_id: nil, entity_ids: nil, client_id: nil, client_secret: nil, new_client_id: nil, new_client_secret: nil, cookies: nil, chomp_v1_from_genesis_endpoint: false, use_api_generated_client_secret: false)
      authorization = ""
      new_client_id = SecureRandom.uuid if new_client_id.blank?
      new_client_secret = SecureRandom.hex(10) if new_client_secret.blank?

      if !cookies.nil?
        authorization = cookies["ZSession"]
        authorization = "ZSession-a3N2w #{authorization}"
        if entity_ids.blank? && cookies["ZuoraCurrentEntity"].present?
          entity_ids = Array(cookies["ZuoraCurrentEntity"].unpack("a8a4a4a4a12").join('-'))
        else
          raise ZuoraAPI::Exceptions::ZuoraAPIError.new("Zuora Entity ID not provided")
        end
        if user_id.blank? && cookies["Zuora-User-Id"].present?
          user_id = cookies["Zuora-User-Id"]
        else
          raise ZuoraAPI::Exceptions::ZuoraAPIError.new("Zuora User ID not provided")
        end
      elsif !client_id.nil? && !client_secret.nil?
        bearer_response = HTTParty.post("https://#{self.hostname}/oauth/token", :headers => {'Content-Type' => 'application/x-www-form-urlencoded', 'Accept' => 'application/json', "User-Agent" => USER_AGENT}, :body => {'client_id' => client_id, 'client_secret' => URI::encode(client_secret), 'grant_type' => 'client_credentials'})
        bearer_hash = JSON.parse(bearer_response.body)
        bearer_token = bearer_hash["access_token"]
        authorization = "Bearer #{bearer_token}"
      end

      if !authorization.blank? && !user_id.blank? && !entity_ids.blank?
        endpoint = chomp_v1_from_genesis_endpoint ? self.rest_endpoint.chomp("v1/").concat("genesis/clients") : self.rest_endpoint("genesis/clients")
        oauth_response = HTTParty.post(endpoint, :headers => {'authorization' => authorization, 'Content-Type' => 'application/json', "User-Agent" => USER_AGENT}, :body => {'clientId' => new_client_id, 'clientSecret' => new_client_secret, 'userId' => user_id, 'entityIds' => entity_ids, 'customAuthorities' => custom_authorities, 'additionalInformation' => {'description' => info_desc, 'name' => info_name}}.to_json)
        output_json = JSON.parse(oauth_response.body)
        if oauth_response.code == 201
          output_json["clientSecret"] = new_client_secret if !use_api_generated_client_secret
          return output_json
        elsif oauth_response.code == 401 && !oauth_response.message.blank?
          raise ZuoraAPI::Exceptions::ZuoraAPIError.new(output_json["message"], oauth_response)
        else
          raise ZuoraAPI::Exceptions::ZuoraAPIError.new(output_json["error"], oauth_response)
        end
      else
        raise ZuoraAPI::Exceptions::ZuoraAPIError.new("Insufficient credentials provided")
      end
    end

    def self.environments
      %w(Sandbox Production Services Performance Staging Test)
    end

    def self.regions
      %w(US EU NA)
    end

    def self.endpoints
      return {"US" => {"Sandbox" => "https://apisandbox.zuora.com/apps/services/a/",
                       "Production" => "https://www.zuora.com/apps/services/a/",
                       "Performance" => "https://pt1.zuora.com/apps/services/a/",
                       "Services" => "https://services347.zuora.com/apps/services/a/",
                       "Staging" => "https://staging2.zuora.com/apps/services/a/",
                       "Test" => "https://test.zuora.com/apps/services/a/"},
              "EU" => {"Sandbox" => "https://sandbox.eu.zuora.com/apps/services/a/",
                       "Production" => "https://eu.zuora.com/apps/services/a/",
                       "Performance" => "https://pt1.eu.zuora.com/apps/services/a/",
                       "Services" => "https://services347.eu.zuora.com/apps/services/a/",
                       "Test" => "https://test.eu.zuora.com/apps/services/a/"},
              "NA" => {"Sandbox" => "https://sandbox.na.zuora.com/apps/services/a/",
                       "Production" => "https://na.zuora.com/apps/services/a/",
                       "Performance" => "https://pt1.na.zuora.com/apps/services/a/",
                       "Services" => "https://services347.na.zuora.com/apps/services/a/"}
            }
    end

    def get_entity_id(entity_id: nil)
      if entity_id.present?
        entity_match = /[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}$/.match(entity_id)
        if entity_match.blank?
          raise "Entity length is wrong." if entity_id.length != 32
          part_one, part_two, part_three, part_four, part_five = [entity_id[0..7], entity_id[8..11], entity_id[12..15], entity_id[16..19], entity_id[20..31]]
          entity_id = "#{part_one}-#{part_two}-#{part_three}-#{part_four}-#{part_five}"
        end
      end
      return entity_id
    end

    def update_region
      if !self.hostname.blank?
        if /(?<=\.|\/|^)(eu)(?=\.|\/|$)/ === self.hostname
          self.region = "EU"
        elsif /(?<=\.|\/|^)(na)(?=\.|\/|$)/ === self.hostname
          self.region = "NA"
        else
          self.region = "US"
        end
      else # This will never happen
        # raise "Can't update region because URL is blank"
        self.region = "Unknown"
      end
    end

    def update_environment
      if !self.hostname.blank?
        case self.hostname
        when /(?<=\.|\/|-|^)(apisandbox|sandbox)(?=\.|\/|-|$)/
          self.environment = 'Sandbox'
        when /(?<=\.|\/|^)(service[\d]*|services[\d]*|ep-edge)(?=\.|\/|$)/
          self.environment = 'Services'
        when /(?<=\.|\/|-|^)(pt[\d]*)(?=\.|\/|-|$)/
          self.environment = 'Performance'
        when /(?<=\.|\/|^)(staging1|staging2|stg)(?=\.|\/|$)/
          self.environment = 'Staging'
        when /(?<=\.|\/|^)(test)(?=\.|\/|$)/
          self.environment = 'Test'
        when /(?<=\.|\/|^)(www|api)(?=\.|\/|$)/, /(^|tls10\.|origin-www\.|zforsf\.|eu\.|na\.)(zuora\.com)/
          self.environment = 'Production'
        else
          self.environment = 'Unknown'
        end
      else # this will never happen
        raise "Can't determine environment from blank URL"
      end
    end

    def update_zconnect_provider
      update_region if self.region.blank?
      update_environment if self.environment.blank?
      mappings = {"US" => {"Sandbox" => "ZConnectSbx",   "Services" => "ZConnectSvcUS", "Production" => "ZConnectProd",   "Performance" => "ZConnectPT1", "Test" => "ZConnectTest", "Staging" => "ZConnectQA", "KubeSTG" => "ZConnectDev", "KubeDEV" => "ZConnectDev", "KubePROD" => "ZConnectDev"},
                  "NA" => {"Sandbox" => "ZConnectSbxNA", "Services" => "ZConnectSvcNA", "Production" => "ZConnectProdNA", "Performance" => "ZConnectPT1NA"},
                  "EU" => {"Sandbox" => "ZConnectSbxEU", "Services" => "ZConnectSvcEU", "Production" => "ZConnectProdEU", "Performance" => "ZConnectPT1EU", "Test" => "ZConnectTest"},
                  "Unknown" => {"Unknown" => "Unknown"}}
      self.zconnect_provider = mappings[self.region][self.environment]
    end

    def aqua_endpoint(url="")
      match = /.*(\/apps\/)/.match(self.url)
      if !match.nil?
        url_slash_apps_slash = match[0]
      else
        raise "self.url has no /apps in it"
      end
      return "#{url_slash_apps_slash}api/#{url}"
    end

    def rest_endpoint(url="", domain=true, prefix='/v1/')
      update_environment
      endpoint = url
      url_postfix = {"US" => ".", "EU" => ".eu.", "NA" => ".na."}[self.region]

      case self.environment
      when 'Test'
        endpoint = "https://rest.test#{url_postfix}zuora.com"
      when 'Sandbox'
        endpoint = "https://rest.sandbox#{url_postfix}zuora.com"
        endpoint = "https://rest.apisandbox.zuora.com"  if self.region == "US"
      when 'Production'
        endpoint = "https://rest#{url_postfix}zuora.com"
      when 'Performance'
        endpoint = "https://rest.pt1.zuora.com"
      when 'Services'
        https = /https:\/\/|http:\/\//.match(self.url)[0]
        host = self.hostname
        endpoint = "#{https}rest#{host}"
      when 'Staging'
        endpoint = "https://rest-staging2.zuora.com"
      when 'Unknown'
        raise "Environment unknown, returning passed in parameter unaltered"
      end
      return domain ? endpoint.concat(prefix).concat(url) : prefix.concat(url)
    end

    def rest_domain(endpoint: self.rest_endpoint)
      return URI(endpoint).host
    end

    def fileURL(url="")
      return self.rest_endpoint("file/").concat(url)
    end

    def dateFormat
      return self.wsdl_number > 68 ? '%Y-%m-%d' : '%Y-%m-%dT%H:%M:%S'
    end

    def new_session(auth_type: :basic, debug: false, zuora_track_id: nil)
      retries ||= 2
      yield

    rescue ZuoraAPI::Exceptions::ZuoraAPISessionError => ex
      self.status = 'Invalid'
      self.current_error = ex.message
      raise
    rescue ZuoraAPI::Exceptions::ZuoraAPIError  => ex
      raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new(ex.message, ex.response)

    rescue ZuoraAPI::Exceptions::ZuoraAPIInternalServerError => ex
      raise ex if retries.zero?

      retries -= 1
      sleep(self.timeout_sleep)
      retry

    rescue *(CONNECTION_EXCEPTIONS + CONNECTION_READ_EXCEPTIONS) => ex
      self.log(location: "BasicLogin", exception: ex, message: "Timed out", level: :error)

      self.current_error = "Request timed out. Try again"
      self.status = 'Timeout'

      raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new(self.current_error)

    rescue EOFError
      if self.url.match?(/.*services\d{1,}.zuora.com*/)
        self.current_error = "Services tenant '#{self.url.scan(/.*\/\/(services\d{1,}).zuora.com*/).last.first}' is no longer available."
        self.status = 'Not Available'
        raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new(self.current_error)
      end

    end

    def get_session(prefix: false, auth_type: :basic, zuora_track_id: nil)
      case auth_type
      when :basic
        if self.current_session.blank?
          case self.class.to_s
          when 'ZuoraAPI::Oauth'
            if self.bearer_token.blank? || self.oauth_expired?
              self.new_session(auth_type: :bearer, zuora_track_id: zuora_track_id)
            end
            self.get_z_session(zuora_track_id: zuora_track_id)
          when 'ZuoraAPI::Basic'
            self.new_session(auth_type: :basic, zuora_track_id: zuora_track_id)
          else
            self.new_session(auth_type: :basic, zuora_track_id: zuora_track_id)
          end
        end
        return prefix ? "ZSession #{self.current_session}" : self.current_session.to_s
      when :bearer
        case self.class.to_s
        when 'ZuoraAPI::Oauth'
          if self.bearer_token.blank? || self.oauth_expired?
            self.new_session(auth_type: :bearer, zuora_track_id: zuora_track_id)
          end
        when 'ZuoraAPI::Basic'
          raise ZuoraAPI::Exceptions::ZuoraAPIAuthenticationTypeError.new("Basic Login, does not support Authentication of Type: #{auth_type}")
        else
          raise ZuoraAPI::Exceptions::ZuoraAPIAuthenticationTypeError.new("Unknown Login, does not support Authentication of Type: #{auth_type}")
        end
        return prefix ? "Bearer #{self.bearer_token}" : self.bearer_token.to_s
      end
    end

    def soap_call(
      ns1: 'ns1',
      ns2: 'ns2',
      batch_size: nil,
      headers: {},
      single_transaction: false,
      debug: false,
      zuora_track_id: nil,
      errors: [ZuoraAPI::Exceptions::ZuoraAPISessionError].concat(ZUORA_API_ERRORS),
      z_session: true,
      timeout_retry: false,
      timeout: 130,
      timeout_sleep_interval: self.timeout_sleep,
      output_exception_messages: true,
      skip_session: false,
      **keyword_args)
      tries ||= 2
      xml = Nokogiri::XML::Builder.new do |xml|
        xml['SOAP-ENV'].Envelope('xmlns:SOAP-ENV' => "http://schemas.xmlsoap.org/soap/envelope/",
                                 "xmlns:#{ns2}" => "http://object.api.zuora.com/",
                                 'xmlns:xsi' => "http://www.w3.org/2001/XMLSchema-instance",
                                 'xmlns:api' => "http://api.zuora.com/",
                                 "xmlns:#{ns1}" => "http://api.zuora.com/") do
          xml['SOAP-ENV'].Header do
            if !skip_session
              xml["#{ns1}"].SessionHeader do
                xml["#{ns1}"].session self.get_session(prefix: false, auth_type: :basic, zuora_track_id: zuora_track_id)
              end
            end
            if single_transaction
              xml["#{ns1}"].CallOptions do
                xml["#{ns1}"].useSingleTransaction single_transaction
              end
            end
            if batch_size
              xml["#{ns1}"].QueryOptions do
                xml["#{ns1}"].batchSize batch_size
              end
            end
          end
          xml['SOAP-ENV'].Body do
            yield xml, keyword_args
          end
        end
      end
      input_xml = Nokogiri::XML(xml.to_xml(:save_with => XML_SAVE_OPTIONS).strip)
      input_xml.xpath('//ns1:session', 'ns1' =>'http://api.zuora.com/').children.remove
      Rails.logger.debug("Request SOAP XML: #{input_xml.to_xml(:save_with => XML_SAVE_OPTIONS).strip}") if debug

      headers.merge!({ 'Content-Type' => "text/xml; charset=utf-8", 'Accept' => 'text/xml'})
      headers['Zuora-Track-Id'] = zuora_track_id if zuora_track_id.present?
      headers['X-Amzn-Trace-Id'] = zuora_track_id if zuora_track_id.present?
      headers["User-Agent"] = USER_AGENT

      request = HTTParty::Request.new(
        Net::HTTP::Post,
        self.url,
        body: xml.doc.to_xml(:save_with => XML_SAVE_OPTIONS).strip,
        headers: headers,
        timeout: timeout,
      )

      response = request.perform

      output_xml = Nokogiri::XML(response.body)
      Rails.logger.debug("Response SOAP XML: #{output_xml.to_xml(:save_with => XML_SAVE_OPTIONS).strip}") if debug

      raise_errors(type: :SOAP, body: output_xml, response: response)

      return output_xml, input_xml, response

    rescue ZuoraAPI::Exceptions::ZuoraAPISessionError => ex
      raise if skip_session
      if !tries.zero? && z_session
        tries -= 1
        Rails.logger.debug("SOAP Call - Session Invalid")

        begin
          self.new_session(auth_type: :basic, zuora_track_id: zuora_track_id)
        rescue *ZUORA_API_ERRORS => ex
          return output_xml, input_xml, ex.response
        end

        retry
      end

      raise ex if errors.include?(ex.class)

      return output_xml, input_xml, response

    rescue *ZUORA_API_ERRORS => ex
      raise ex if errors.include?(ex.class)

      response = ex.response unless response
      return output_xml, input_xml, response

    rescue *CONNECTION_EXCEPTIONS => ex
      if !tries.zero?
        tries -= 1
        self.log(location: "SOAP Call", exception: ex, message: "Timed out will retry after #{timeout_sleep_interval} seconds", level: :debug)
        sleep(timeout_sleep_interval)
        retry
      end

      self.log(location: "SOAP Call", exception: ex, message: "Timed out", level: :error)  if output_exception_messages
      raise ex

    rescue *CONNECTION_READ_EXCEPTIONS => ex
      if !tries.zero?
        tries -= 1
        self.log(location: "SOAP Call", exception: ex, message: "Timed out will retry after #{timeout_sleep_interval} seconds", level: :debug)
        if ex.is_a?(Errno::ECONNRESET) && ex.message.include?('SSL_connect')
          retry
        elsif timeout_retry
          sleep(timeout_sleep_interval)
          retry
        end
      end

      self.log(location: "SOAP Call", exception: ex, message: "Timed out", level: :error)  if output_exception_messages
      ex = ZuoraAPI::Exceptions::ZuoraAPIReadTimeout.new("Received read/write timeout from 'https://#{rest_domain(endpoint: url)}'", nil, request) if ex.is_a?(Timeout::Error) && !ex.instance_of?(ZuoraAPI::Exceptions::ZuoraAPIReadTimeout)
      raise ex

    rescue => ex
      raise ex
    ensure
      self.error_logger(ex) if defined?(ex)
    end

    def error_logger(ex)
      return unless Rails.logger.is_a? Ougai::Logger

      exception_args = Rails.logger.with_fields.merge(self.exception_args(ex))
      case ex
      when ZuoraAPI::Exceptions::ZuoraAPIUnkownError, ZuoraAPI::Exceptions::ZuoraDataIntegrity
        Rails.logger.error('Zuora Unknown/Integrity Error', ex, exception_args)
      when ZuoraAPI::Exceptions::ZuoraAPIRequestLimit
        Rails.logger.info('Zuora APILimit Reached', ex, exception_args)
      when *(ZuoraAPI::Login::ZUORA_API_ERRORS-ZuoraAPI::Login::ZUORA_SERVER_ERRORS)
        #Rails.logger.debug('Zuora API Error', ex, self.exception_args(ex))
      when *ZuoraAPI::Login::ZUORA_SERVER_ERRORS
        Rails.logger.error('Zuora Server Error', ex, exception_args)
      end
    end

    def log(location: "Rest Call", exception: nil, message: "Timed out will retry after #{self.timeout_sleep} seconds", level: :info )
      level = :debug if ![:debug, :info, :warn, :error, :fatal].include?(level)
      if Rails.logger.is_a? Ougai::Logger
        Rails.logger.send(level.to_sym, "#{location} - #{message}", exception)
      else
        Rails.logger.send(level.to_sym, "#{location} - #{exception.class} #{message}")
      end
    end

    def exception_args(ex)
      args = {}
      if defined?(ex.response) && ex.response.present?
        args.merge!({
          url: {full: ex.response.request.path.to_s},
          request: {
            method: ex.response.request.http_method.to_s.split("Net::HTTP::").last.upcase,
            params: ex.response.request.raw_body.to_s,
            headers: ex.response.request.options[:headers].map{|k,v| [k.to_s, k.to_s.downcase.strip == "authorization" ? "VALUE FILTERED" : v]}.to_h,
          },
          response: {
            status: ex.response.code,
            params: ex.response.body.to_s,
            headers: ex.response.headers,
          },
          zuora_trace_id: ex.response.headers["zuora-request-id"],
          zuora_track_id: ex.response.request.options[:headers]["Zuora-Track-Id"],
        })
      elsif defined?(ex.request) && ex.request.present?
        args.merge!({
          url: {full: ex.request.path.to_s},
          request: {
            method: ex.request.http_method.to_s.split("Net::HTTP::").last.upcase,
            params: ex.request.options[:body],
            headers: ex.request.options[:headers].map{|k,v| [k.to_s, k.to_s.downcase.strip == "authorization" ? "VALUE FILTERED" : v]}.to_h
          }
        })
        args.merge!({
          zuora_track_id: ex.request.options[:headers]["Zuora-Track-Id"]
        }) if ex.request.options[:headers]["Zuora-Track-Id"].present?
      end
    rescue => ex
      Rails.logger.error("Failed to create exception arguments", ex, args)
    ensure
      return args
    end

    def raise_errors(type: :SOAP, body: nil, response: nil)
      request_uri, request_path, match_string = "", "", ""
      if response.class.to_s == "HTTP::Message"
        request_uri = response.http_header.request_uri.to_s
        request_path = response.http_header.request_uri.path
        match_string = "#{response.http_header.request_method}::#{response.code}::#{request_uri}"
      else
        request = response.request
        request_uri = response.request.uri
        request_path = request.path.path
        match_string = "#{request.http_method.to_s.split("Net::HTTP::").last.upcase}::#{response.code}::#{request_path}"
      end

      if [502,503].include?(response.code)
        raise ZuoraAPI::Exceptions::ZuoraAPIConnectionTimeout.new("Received #{response.code} from 'https://#{rest_domain(endpoint: request_uri)}'", response)
      end

      # Check failure response code
      case response.code
      when 504
        raise ZuoraAPI::Exceptions::ZuoraAPIReadTimeout.new("Received 504 from 'https://#{rest_domain(endpoint: request_uri)}'", response)
      when 429
        raise ZuoraAPI::Exceptions::ZuoraAPIRequestLimit.new("The total number of concurrent requests has exceeded the limit allowed by the system. Please resubmit your request later.", response)
      when 401

      else
        if body.class == Hash
          case request_path
          when /^\/v1\/connections$/
            response_headers = response.headers.to_h
            raise ZuoraAPI::Exceptions::ZuoraAPIInternalServerError.new("Missing cookies for authentication call", response) if response_headers['set-cookie'].blank?
            z_session_cookie = response_headers.fetch('set-cookie', []).select{|x| x.match(/^ZSession=.*/) }.first
            raise ZuoraAPI::Exceptions::ZuoraAPIInternalServerError.new("Missing ZSession cookie for authentication call", response) if z_session_cookie.blank?
          end
        end
      end

      case type
      when :SOAP
        error, success, message = get_soap_error_and_message(body)

        if body.xpath('//fns:LoginFault', 'fns' =>'http://fault.api.zuora.com/').present?
          raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new(message, response)
        end

        if body.xpath('//ns1:queryResponse', 'ns1' => 'http://api.zuora.com/').present? &&
           body.xpath(
             '//ns1:records[@xsi:type="ns2:Export"]',
             'ns1' => 'http://api.zuora.com/', 'xsi' => 'http://www.w3.org/2001/XMLSchema-instance'
           ).present?
          result = body.xpath('//ns2:Status', 'ns2' => 'http://object.api.zuora.com/').text
          if result == 'Failed'
            message = body.xpath('//ns2:StatusReason', 'ns2' => 'http://object.api.zuora.com/').text
            error = 'UNEXPECTED_ERROR'
            if message.present?
              identifier, new_message = message.scan(/^([\w\d]{16})\: (.*)/).first
              error, message = ['UNEXPECTED_ERROR', new_message] if new_message.present?
              error, message = ['TRANSACTION_FAILED', new_message.concat(" Please see KC for the Max Timeout Specification https://community.zuora.com/t5/Release-Notifications/Upcoming-Change-for-AQuA-and-Data-Source-Export-January-2021/ba-p/35024")] if new_message.include?("The query exceeded maximum processing time")
            else
              message = 'Export failed due to unknown reason. Consult api logs.'
            end
          end
        end

        #By default response if not passed in for SOAP as all SOAP is 200
        if error.present?
          if error.class == String
            raise_errors_helper(error: error, message: message, response: response)
          elsif error.class == Array
            if error.uniq.size == 1
              err, msg = error[0].split('::')
              raise_errors_helper(error: err, message: msg, response: response, errors: error, success: success)
            else
              raise ZuoraAPI::Exceptions::ZuoraAPIError.new(error.group_by {|v| v}.map {|k,v| "(#{v.size}x) - #{k == "::" ? 'UNKNOWN::No error provided' : k}"}.join(', '), response, error, success)
            end
          end
        end

        self.errors_via_content_type(response: response, type: :xml)

      when :JSON
        case request_path
        when /^\/query\/jobs.*/  #DataQuery Paths
          return if body.class != Hash
          case match_string
          when /^GET::200::\/query\/jobs\/([a-zA-Z0-9\-_]+)$/ #Get DQ job, Capture of the id is present if needed in future error responses.
            if body.dig('data', "errorCode") == "LINK_10000005"
              raise ZuoraAPI::Exceptions::ZuoraAPITemporaryError.new(body.dig('data', "errorMessage"), response)
            elsif (body.dig('data', "errorMessage").present? || body.dig('data', "queryStatus") == "failed")
              raise ZuoraAPI::Exceptions::ZuoraAPIError.new(body.dig('data', "errorMessage"), response)
            end
          when /^GET::404::\/query\/jobs\/([a-zA-Z0-9\-_]+)$/ #Get DQ job not found, capture of the id is present if needed in future error responses.
            raise ZuoraAPI::Exceptions::ZuoraAPIError.new(body.dig('message'), response) if body.dig('message').present?
          when /^POST::400::\/query\/jobs$/ #Create DQ job
            raise ZuoraAPI::Exceptions::ZuoraAPIError.new(body.dig('message'), response) if body.dig('message').present?
          end
        when /^\/api\/rest\/v1\/reports.*/  #Reporting Paths
          reporting_message = response.parsed_response.dig("ZanResponse", "response", "message") || body.dig("message")
          if reporting_message&.include?("com.zuora.rest.RestUsageException: The user does not have permissions for this API.")
            raise ZuoraAPI::Exceptions::ZuoraAPIError.new(reporting_message, response)
          elsif reporting_message&.include?("500 Internal Server Error")
            raise ZuoraAPI::Exceptions::ZuoraAPIInternalServerError.new("Internal Server Error. The Reporting API is down. Contact Support.", response)
          end
          case match_string
          when /^GET::400::\/api\/rest\/v1\/reports\/(reportlabels\/)?([a-zA-Z0-9\-_]+)\/report-details$/ # Get report, capture of the id is present if needed in future error responses.
            raise ZuoraAPI::Exceptions::ZuoraAPIError.new(reporting_message, response) if reporting_message.present?
          end
        when /\/objects\/batch\//
          if body['code'].present? && /61$/.match(body['code'].to_s).present? # if last 2 digits of code are 61
            raise ZuoraAPI::Exceptions::ZuoraAPITemporaryError.new(body['message'], nil, body['details'])
          end
        when /^\/api\/v1\/payment_plans.*/
           raise ZuoraAPI::Exceptions::ZuoraAPIError.new(body['error'], response) if body['error']
        end

        body = body.dig("results").present? ? body["results"] : body if body.class == Hash
        if body.class == Hash && (!(body["success"] || body["Success"]) || response.code != 200)
          reason_keys = %w(reasons errors)
          message_keys = %w(message title)
          messages_array, codes_array = [[],[]]
          reason_keys.each do |rsn_key|
            message_keys.each do |msg_key|
              messages_array = body.fetch(rsn_key, []).map {|error| error[msg_key]}.compact
              break if messages_array.present?
            end
            codes_array = body.fetch(rsn_key, []).map {|error| error['code']}.compact
            break if messages_array.present? && codes_array.present?
          end
          if body.dig('error').class == Hash
            messages_array = messages_array.push(body.dig("error", 'message')).compact
            codes_array = codes_array.push(body.dig("error", 'code')).compact
          end

          if body['message'] == 'request exceeded limit'
            raise ZuoraAPI::Exceptions::ZuoraAPIRequestLimit.new("The total number of concurrent requests has exceeded the limit allowed by the system. Please resubmit your request later.", response)
          end

          if (body.dig('message') || '').downcase.include?('unexpected error') && response.code != 500
            raise ZuoraAPI::Exceptions::ZuoraUnexpectedError.new(body['message'], response)
          end

          if body['message'] == "No bearer token" && response.code == 400
            raise ZuoraAPI::Exceptions::ZuoraAPIAuthenticationTypeError.new("Authentication type is not supported by this Login", response)
          end

          if body['errorMessage']
            raise ZuoraAPI::Exceptions::ZuoraAPIError.new(body['errorMessage'], response)
          end

          if body.dig("reasons").nil? ? false : body.dig("reasons")[0].dig("code") == 90000020
            raise ZuoraAPI::Exceptions::BadEntityError.new("#{messages_array.join(', ')}", response)
          end

          #Oauth Tokens - User deactivated
          if body['path'] == '/oauth/token'
            if body['status'] == 403 && response.code == 403
              raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new("Forbidden", response)
            elsif body['status'] == 400 && response.code == 400 && body['message'].include?("Invalid client id")
              raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new("Invalid Oauth Client Id", response)
            end
          end

          if body['error'] == 'Unauthorized' && body['status'] == 401
            if body['message'].present?
              raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new(body['message'], response)
            else
              raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new("#{messages_array.join(', ')}", response)
            end
          end
          #Authentication failed
          if (codes_array.map{|code| code.to_s.slice(6,7).to_i}.include?(11) || response.code == 401) && !codes_array.include?(422)
            new_message = messages_array.join(', ')
            if new_message.present?
              raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new(new_message, response)
            else
              raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new(body['message'], response)
            end
          end

          #Zuora REST Create Amendment error #Authentication failed
          if body["faultcode"].present? && body["faultcode"] == "fns:INVALID_SESSION"
            raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new("#{body['faultstring']}", response)
          end

          #Locking contention
          if codes_array.map{|code| code.to_s.slice(6,7).to_i}.include?(50)
            raise ZuoraAPI::Exceptions::ZuoraAPILockCompetition.new("#{messages_array.join(', ')}", response)
          end
          #Internal Server Error
          if codes_array.map{|code| code.to_s.slice(6,7).to_i}.include?(60)
            if messages_array.uniq.size == 1
              if messages_array.first.match(/^Transaction declined.*|^There is an invoice pending tax.*|^The Zuora GetTax call to Avalara.*|^The tax calculation call to Zuora Connect returned the following error: Status Code: 4.*/)
                raise ZuoraAPI::Exceptions::ZuoraAPIError.new(messages_array.first, response)
              end
            end
            raise ZuoraAPI::Exceptions::ZuoraAPIInternalServerError.new("#{messages_array.join(', ')}", response)
          end

          #Retryiable Service Error
          if codes_array.map{|code| code.to_s.slice(6,7).to_i}.include?(61)
            raise ZuoraAPI::Exceptions::ZuoraAPITemporaryError.new("#{messages_array.join(', ')}", response)
          end

          #Request exceeded limit
          if codes_array.map{|code| code.to_s.slice(6,7).to_i}.include?(70)
            raise ZuoraAPI::Exceptions::ZuoraAPIRequestLimit.new("#{messages_array.join(', ')}", response)
          end

          #All Errors catch
          if codes_array.size > 0
            raise ZuoraAPI::Exceptions::ZuoraAPIError.new("#{messages_array.join(', ')}", response)
          end

          #Zuora REST Query Errors
          if body["faultcode"].present?
            raise_errors_helper(error:  body["faultcode"], message: body["faultstring"], response: response)
          end

          if body["Errors"].present? || body["errors"].present?
            codes, messages = [[],[]]
            body.fetch("Errors", []).each { |obj| messages.push(obj["Message"]); messages.push(obj["title"]); codes.push(obj["Code"]); codes.push(obj["code"]) }
            body.fetch("errors", []).each { |obj| messages.push(obj["Message"]); messages.push(obj["title"]); codes.push(obj["Code"]); codes.push(obj["code"]) }
            codes, messages = [codes.uniq.compact, messages.uniq.compact]
            if codes.size > 0
              if codes.size == 1
                raise_errors_helper(error: codes.first, message: messages.first, response: response, errors: messages)
              else
                raise ZuoraAPI::Exceptions::ZuoraAPIError.new("#{messages.join(", ")}", response, messages)
              end
            end
          end
        end

        #Zuora REST Actions error (Create, Update, Delete, Amend)
        if body.class == Array
          all_errors = body.select {|obj| !obj['Success'] || !obj['success'] }.map {|obj| obj['Errors'] || obj['errors'] }.compact
          all_success = body.select {|obj| obj['Success'] || obj['success']}.compact

          if all_success.blank? && all_errors.present?
            error_codes = all_errors.flatten.group_by {|error| error['Code']}.keys.uniq
            error_messages = all_errors.flatten.group_by {|error| error['Message']}.keys.uniq
            if error_codes.size == 1 || error_messages.size == 1
              if error_codes.first == "LOCK_COMPETITION"
                raise ZuoraAPI::Exceptions::ZuoraAPILockCompetition.new("Retry Lock Competition", response)
              elsif error_messages.first.include?("data integrity violation")
                raise ZuoraAPI::Exceptions::ZuoraDataIntegrity.new("Data Integrity Violation", response)
              end
            end
          end

          if all_errors.size > 0
            raise ZuoraAPI::Exceptions::ZuoraAPIError.new("#{all_errors.flatten.group_by {|error| error['Message']}.keys.uniq.join(' ')}", response, all_errors, all_success)
          end
        end

        if body.class == Hash && body['message'].present?
          raise ZuoraAPI::Exceptions::ZuoraAPIInternalServerError.new(body['message'], response) if response.code == 500
          raise ZuoraAPI::Exceptions::ZuoraAPIError.new(body['message'], response) if ![200,201].include?(response.code)
        end

        self.errors_via_content_type(response: response, type: :json)

        #All other errors
        raise ZuoraAPI::Exceptions::ZuoraAPIError.new(response.body, response) if ![200,201].include?(response.code)
      end
    end

    def errors_via_content_type(response: nil, type: :xml)
      response_content_types = response.headers.transform_keys(&:downcase).fetch('content-type', []).first || ""

      if response_content_types.include?('application/json') && type != :json
        output_json = JSON.parse(response.body)
        self.raise_errors(type: :JSON, body: output_json, response: response)

      elsif (response_content_types.include?('application/xml') || response_content_types.include?('text/xml') || response_content_types.include?('application/soap+xml')) and type != :xml
        output_xml = Nokogiri::XML(response.body)
        self.raise_errors(type: :SOAP, body: output_xml, response: response)

      elsif response_content_types.include?('text/html')
        raise ZuoraAPI::Exceptions::ZuoraAPIInternalServerError.new("Akamai Error", response) if response.headers.fetch('server', '') == 'AkamaiGHost'

        parse_body = Nokogiri::HTML(response.body)
        error_title = parse_body.xpath('//h2').text
        error_title = parse_body.xpath('//h1').text if error_title.blank?
        error_message = parse_body.xpath('//p').text

        error_message = error_title if error_message.blank?

        if error_title.present?
          case error_title
          when /Service Unavailable/
            raise ZuoraAPI::Exceptions::ZuoraAPIConnectionTimeout.new(error_message, response)
          when /Client sent a bad request./, /Bad Request/, /403 Forbidden/
            raise ZuoraAPI::Exceptions::ZuoraAPIInternalServerError.new(error_message, response)
          when /414 Request-URI Too Large/
            raise ZuoraAPI::Exceptions::ZuoraAPIError.new("Request URL is too long", response)
          else
            raise ZuoraAPI::Exceptions::ZuoraAPIInternalServerError.new(error_message, response)
          end
        end

        raise ZuoraAPI::Exceptions::ZuoraAPIInternalServerError.new("Http response body is missing", response) if response.body.blank?
      end

      raise ZuoraAPI::Exceptions::ZuoraAPIInternalServerError.new(response.body, response) if response.code == 500
    end


    def get_soap_error_and_message(body)
      error   = body.xpath('//fns:FaultCode', 'fns' =>'http://fault.api.zuora.com/').text
      message = body.xpath('//fns:FaultMessage', 'fns' =>'http://fault.api.zuora.com/').text

      if error.blank? || message.blank?
        error   = body.xpath('//faultcode').text
        message = body.xpath('//faultstring').text
      end

      if error.blank? || message.blank?
        error   = body.xpath('//ns1:Code', 'ns1' =>'http://api.zuora.com/').text
        message = body.xpath('//ns1:Message', 'ns1' =>'http://api.zuora.com/').text
      end

      if error.blank? || message.blank?
        error   = body.xpath('//soapenv:Value', 'soapenv'=>'http://www.w3.org/2003/05/soap-envelope').text
        message = body.xpath('//soapenv:Text', 'soapenv'=>'http://www.w3.org/2003/05/soap-envelope').text
      end

      #Update/Create/Delete Calls with multiple requests and responses
      if body.xpath('//ns1:result', 'ns1' =>'http://api.zuora.com/').size > 0 && body.xpath('//ns1:Errors', 'ns1' =>'http://api.zuora.com/').size > 0
        error = []
        success = []
        body.xpath('//ns1:result', 'ns1' =>'http://api.zuora.com/').each_with_index do |call, object_index|
          if call.xpath('./ns1:Success', 'ns1' =>'http://api.zuora.com/').text == 'false' && call.xpath('./ns1:Errors', 'ns1' =>'http://api.zuora.com/').size > 0
            message = "#{call.xpath('./*/ns1:Code', 'ns1' =>'http://api.zuora.com/').text}::#{call.xpath('./*/ns1:Message', 'ns1' =>'http://api.zuora.com/').text}"
            error.push(message)
          else
            success.push(call.xpath('./ns1:Id', 'ns1' =>'http://api.zuora.com/').text)
          end
        end
      end
      return error, success, message
    end

    def raise_errors_helper(error: nil, message: nil, response: nil, errors: [], success: [])
      case error
      when /.*INVALID_SESSION/
        raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new(message, response, errors, success)
      when /.*REQUEST_EXCEEDED_LIMIT/
        raise ZuoraAPI::Exceptions::ZuoraAPIRequestLimit.new(message, response, errors, success)
      when /.*LOCK_COMPETITION/
        raise ZuoraAPI::Exceptions::ZuoraAPILockCompetition.new(message, response, errors, success)
      when /.*BATCH_FAIL_ERROR/
        if message.include?("optimistic locking failed") || message.include?("Operation failed due to a lock competition, please retry later.")
          raise ZuoraAPI::Exceptions::ZuoraAPILockCompetition.new(message, response, errors, success)
        elsif message.include?("org.hibernate.exception.ConstraintViolationException")
          raise ZuoraAPI::Exceptions::ZuoraAPIInternalServerError.new(message, response, errors, success)
        end
        raise ZuoraAPI::Exceptions::ZuoraAPIError.new(message, response, errors, success)
      when /.*TEMPORARY_ERROR/, /.*TRANSACTION_TIMEOUT/
        raise ZuoraAPI::Exceptions::ZuoraAPITemporaryError.new(message, response, errors, success)
      when /.*INVALID_VALUE/
        if message.include?("data integrity violation")
          raise ZuoraAPI::Exceptions::ZuoraDataIntegrity.new("Data Integrity Violation", response, errors), success
        end
        raise ZuoraAPI::Exceptions::ZuoraAPIError.new(message, response, errors, success)
      when /.*UNKNOWN_ERROR/
        if /payment\/refund|Credit Balance Adjustment|Payment Gateway|ARSettlement permission/.match(message).nil?
          raise ZuoraAPI::Exceptions::ZuoraAPIUnkownError.new(message, response, errors, success)
        end
        raise ZuoraAPI::Exceptions::ZuoraAPIError.new(message, response, errors, success)
      when /^INVALID_VERSION/, /invalid/, /^DUPLICATE_VALUE/, /^REQUEST_REJECTED/, /INVALID_ID/, /MAX_RECORDS_EXCEEDED/, /INVALID_FIELD/, /MALFORMED_QUERY/, /NO_PERMISSION/, /PDF_QUERY_ERROR/, /MISSING_REQUIRED_VALUE/, /INVALID_TYPE/, /TRANSACTION_FAILED/, /API_DISABLED/, /CANNOT_DELETE/, /ACCOUNTING_PERIOD_CLOSED/
        raise ZuoraAPI::Exceptions::ZuoraAPIError.new(message, response, errors, success)
      when /.*UNEXPECTED_ERROR/
        raise ZuoraAPI::Exceptions::ZuoraUnexpectedError.new(message, response, errors, success)
      when /.*soapenv:Server.*/
        if /^Invalid value.*for type.*|^Id is invalid|^date string can not be less than 19 charactors$/.match(message).present?
          raise ZuoraAPI::Exceptions::ZuoraAPIError.new(message, response, errors, success)
        elsif /^unknown$|^Invalid white space character \(.*\) in text to output$|^Invalid null character in text to output$/.match(message).present?
          raise ZuoraAPI::Exceptions::ZuoraAPIUnkownError.new(message, response, errors, success)
        end
        raise ZuoraAPI::Exceptions::ZuoraAPIInternalServerError.new(message, response, errors, success)
      when /soapenv:Receiver/
        if /^com.ctc.wstx.exc.WstxUnexpectedCharException: Unexpected character.*$/.match(message).present?
          raise ZuoraAPI::Exceptions::ZuoraAPIError.new(message, response, errors, success)
        end
        raise ZuoraAPI::Exceptions::ZuoraAPIInternalServerError.new(message, response, errors, success)
      else
        raise ZuoraAPI::Exceptions::ZuoraAPIInternalServerError.new("Z:#{error}::#{message}", response, errors, success)
      end
    end

    def aqua_query(queryName: '', query: '', version: '1.2', jobName: 'Aqua',partner: '', project: '')
      params = {
        "format" => 'csv',
        "version" => version,
        "name" => jobName,
        "encrypted" => 'none',
        "useQueryLabels" => 'true',
        "partner" => partner,
        "project" => project,
        "queries" => [{
          "name" => queryName,
          "query" => query,
          "type" => 'zoqlexport'
          }]
      }
      response = self.rest_call(method: :post, body: params.to_json, url: self.aqua_endpoint("batch-query/"))
      if(response[0]["id"].nil?)
        raise ZuoraAPI::Exceptions::ZuoraAPIError.new("Error in AQuA Process.", response)
      end
      return getFileById(id: response[0]["id"])
    end

    def getFileById(id: "2c92c0f85e7f88ff015e86b8f8f4517f")
      response = nil
      result = "new"
      while result != "completed" do
        sleep(2)#sleep 2 seconds
        response, fullResponse = self.rest_call(method: :get, body: {}, url: self.aqua_endpoint("batch-query/jobs/#{id}"))
        result = response["batches"][0]["status"]
        if result == "error"
          raise ZuoraAPI::Exceptions::ZuoraAPIError.new("Aqua Error", response)
          break
        end
      end
      fileId = response["batches"][0]["fileId"]
      return self.get_file(url: self.aqua_endpoint("file/#{fileId}"))
    end

    def entity_header
      if self.entity_header_type == :entity_name && self.entity_identifier.present?
        { "entityName" => self.entity_identifier }
      elsif self.entity_id.present?
        { "Zuora-Entity-Ids" => self.entity_id }
      else
        {}
      end
    end

    def insert_entity_header(destination_headers, lookup_headers: nil)
      # The entity header may be added to a place other than where we look for it
      lookup_headers = destination_headers if lookup_headers.nil?

      entity_header_options = %w(zuora-entity-ids entityid entityname)
      # If the customer doesn't supply an entity header, fill it in
      if (entity_header_options & lookup_headers.keys.map(&:downcase)).blank?
        entity_header = self.entity_header
        if entity_header.present?
          destination_headers.merge!(entity_header)
          entity_header_options_to_exclude =
            entity_header_options.
              reject { |header| header == entity_header.keys.first&.downcase }
          destination_headers.delete_if { |key, _| entity_header_options_to_exclude.include?(key.to_s.downcase) }
        end
      end
    end

    def describe_call(object = nil, log_errors = true)
      tries ||= 2
      base = self.url.include?(".com") ? self.url.split(".com")[0].concat(".com") : self.url.split(".eu")[0].concat(".eu")
      version = self.url.scan(/(\d+\.\d)$/).dig(0,0).to_f
      url = object ? "#{base}/apps/api/#{version}/describe/#{object}" : "#{base}/apps/api/#{version}/describe/"

      headers = { "Content-Type" => "text/xml; charset=utf-8" }.merge(self.entity_header)
      response = HTTParty.get(url,  headers: {"Authorization" => self.get_session(prefix: true, auth_type: :basic), "User-Agent" => USER_AGENT}.merge(headers), :timeout => 130)

      raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new(self.current_error.present? ? self.current_error : 'Describe call 401', response) if response.code == 401

      output_xml = Nokogiri::XML(response.body)
      des_hash = Hash.new
      if object == nil
        output_xml.xpath("//object").each do |object|
          temp = {:label => object.xpath(".//label").text, :url => object.attributes["href"].value }
          des_hash[object.xpath(".//name").text] = temp
        end
      else
        output_xml.xpath("//field").each do |object|
          temp = {:label => object.xpath(".//label").text,:selectable => object.xpath(".//selectable").text,
                  :createable => object.xpath(".//label").text == "ID" ? "false" : object.xpath(".//createable").text,
                  :filterable => object.xpath(".//filterable").text,
                  :updateable => object.xpath(".//label").text == "ID" ? "false" : object.xpath(".//updateable").text,
                  :custom => object.xpath(".//custom").text,:maxlength => object.xpath(".//maxlength").text,
                  :required => object.xpath(".//required").text,
                  :type => object.xpath(".//type").text,
                  :context => object.xpath(".//context").collect{ |x| x.text } }
          temp[:options] = object.xpath(".//option").collect{ |x| x.text } if object.xpath(".//option").size > 0
          des_hash[object.xpath(".//name").text.to_sym] = temp
          des_hash[:fieldsToNull] = {:label => "FieldsToNull",:selectable => "false",
                                     :createable => "false",:filterable => "false",
                                     :updateable => "true",:custom => "false",
                                     :required => "false",:type => "picklist",
                                     :maxlength => "" ,:context => ["soap"],
                                     :options => des_hash.map {|k,v| k if  v[:updateable] == "true" && v[:required] == "false"}.compact.uniq }

        end
        des_hash[:related_objects] = output_xml.xpath(".//related-objects").xpath(".//object").map{ |x| [x.xpath(".//name").text.to_sym, [ [:url, x.attributes["href"].value], [:label, x.xpath(".//name").text ] ].to_h] }.to_h
      end

      return des_hash
    rescue *(CONNECTION_EXCEPTIONS + CONNECTION_READ_EXCEPTIONS) => ex
      if !tries.zero?
        tries -= 1
        self.log(location: "Describe", exception: ex, message: "Timed out will retry after #{self.timeout_sleep} seconds", level: :debug)
        sleep(self.timeout_sleep)
        retry
      end

      self.log(location: "Describe", exception: ex, message: "Timed out", level: :error) if log_errors
      raise ex

    rescue ZuoraAPI::Exceptions::ZuoraAPISessionError => ex
      if !tries.zero? && self.status == 'Active'
        tries -= 1
        Rails.logger.debug("Describe session expired. Starting new session.")
        self.new_session
        retry
      end

      Rails.logger.error("Describe session expired. Starting new session.") if log_errors
      raise ex
    rescue => ex
      raise ex
    end

    def rest_call(
      method: :get,
      body: nil,
      headers: {},
      url: rest_endpoint("catalog/products?pageSize=4"),
      debug: false,
      errors: [ZuoraAPI::Exceptions::ZuoraAPISessionError].concat(ZUORA_API_ERRORS),
      z_session: true,
      session_type: :basic,
      timeout_retry: false,
      timeout: 130,
      timeout_sleep_interval: self.timeout_sleep,
      multipart: false,
      stream_body: false,
      output_exception_messages: true,
      zuora_track_id: nil,
      **keyword_args,
      &block
    )
      tries ||= 2

      raise "Method not supported, supported methods include: :get, :post, :put, :delete, :patch, :head, :options" if ![:get, :post, :put, :delete, :patch, :head, :options].include?(method)

      authentication_headers = {}
      if z_session
        authentication_headers = {"Authorization" => self.get_session(prefix: true, auth_type: session_type, zuora_track_id: zuora_track_id) }

        self.insert_entity_header(authentication_headers, lookup_headers: headers)
      end
      headers['Zuora-Track-Id'] = zuora_track_id if zuora_track_id.present?
      headers['X-Amzn-Trace-Id'] = zuora_track_id if zuora_track_id.present?
      headers['User-Agent'] = USER_AGENT

      modified_headers = {'Content-Type' => "application/json; charset=utf-8"}.merge(authentication_headers).merge(headers)

      begin
        request = HTTParty::Request.new(
          "Net::HTTP::#{method.to_s.capitalize}".constantize,
          url,
          body: body,
          headers: modified_headers,
          timeout: timeout,
          multipart: multipart,
          stream_body: stream_body
        )

        response = request.perform(&block)

        Rails.logger.debug("Response Code: #{response.code}") if debug
        begin
          output_json = JSON.parse(response.body)
        rescue JSON::ParserError => ex
          output_json = {}
        end
        Rails.logger.debug("Response JSON: #{output_json}") if debug && output_json.present?

        raise_errors(type: :JSON, body: output_json, response: response)
      rescue => ex
        reset_files(body) if multipart
        raise
      end

      return [output_json, response]
    rescue ZuoraAPI::Exceptions::ZuoraAPIAuthenticationTypeError => ex
      if self.class.to_s == 'ZuoraAPI::Oauth' && ex.message.include?("Authentication type is not supported by this Login")
        session_type = :bearer
        retry
      end
      Rails.logger.debug("Rest Call - Session Bad Auth type")
      raise ex

    rescue ZuoraAPI::Exceptions::ZuoraAPISessionError => ex
      if !tries.zero? && z_session
        tries -= 1
        Rails.logger.debug("Rest Call - Session Invalid #{session_type}")

        begin
          self.new_session(auth_type: session_type)
        rescue *ZUORA_API_ERRORS => ex
          return [output_json, ex.response]
        end

        retry
      end

      raise ex if errors.include?(ex.class)
      return [output_json, response]

    rescue *ZUORA_API_ERRORS => ex
      raise ex if errors.include?(ex.class)

      response = ex.response unless response
      return [output_json, response]

    rescue ZuoraAPI::Exceptions::BadEntityError => ex
      raise ex
    rescue *CONNECTION_EXCEPTIONS => ex
      if !tries.zero?
        tries -= 1
        self.log(location: "Rest Call", exception: ex, message: "Timed out will retry after #{timeout_sleep_interval} seconds", level: :debug)
        sleep(timeout_sleep_interval)
        retry
      end

      self.log(location: "Rest Call", exception: ex, message: "Timed out", level: :error) if output_exception_messages
      raise ex

    rescue *CONNECTION_READ_EXCEPTIONS => ex

      if !tries.zero?
        tries -= 1
        self.log(location: "Rest Call", exception: ex, message: "Timed out will retry after #{timeout_sleep_interval} seconds", level: :debug)
        if ex.is_a?(Errno::ECONNRESET) && ex.message.include?('SSL_connect')
          retry
        elsif timeout_retry
          sleep(timeout_sleep_interval)
          retry
        end
      end

      self.log(location: "Rest Call", exception: ex, message: "Timed out", level: :error) if output_exception_messages
      ex = ZuoraAPI::Exceptions::ZuoraAPIReadTimeout.new("Received read/write timeout from 'https://#{rest_domain(endpoint: url)}'", nil, request) if ex.is_a?(Timeout::Error) && !ex.instance_of?(ZuoraAPI::Exceptions::ZuoraAPIReadTimeout)
      raise ex

    rescue => ex
      raise ex
    ensure
      self.error_logger(ex) if defined?(ex)
    end

    def update_create_tenant
      Rails.logger.debug("Update and/or Create Tenant")
      output_xml, input_xml = soap_call() do |xml|
        xml['api'].getUserInfo
      end
      user_info = output_xml.xpath('//ns1:getUserInfoResponse', 'ns1' =>'http://api.zuora.com/')
      output_hash = Hash[user_info.children.map {|x| [x.name.to_sym, x.text] }]
      self.user_info = output_hash
      self.user_info['entities'] = self.rest_call(:url => self.rest_endpoint("user-access/user-profile/#{self.user_info['UserId']}/accessible-entities"))['entities']
      self.tenant_name = output_hash[:TenantName]
      self.tenant_id = output_hash[:TenantId]
      return self
    end

    def get_catalog(page_size: 40)
      products, catalog_map, response = [{}, {}, {'nextPage' => self.rest_endpoint("catalog/products?pageSize=#{page_size}") }]
      while !response["nextPage"].blank?
        url = self.rest_endpoint(response["nextPage"].split('/v1/').last)
        Rails.logger.debug("Fetch Catalog URL #{url}")
        output_json, response = self.rest_call(debug: false, url: url, timeout_retry: true)

        if !/(true|t|yes|y|1)$/.match(output_json['success'].to_s) || output_json['success'].class != TrueClass
          raise ZuoraAPI::Exceptions::ZuoraAPIError.new("Error Getting Catalog: #{output_json}", response)
        end
        output_json["products"].each do |product|
          catalog_map[product["id"]] = {"productId" => product["id"]}
          rateplans = {}

          product["productRatePlans"].each do |rateplan|
            catalog_map[rateplan["id"]] = {"productId" => product["id"], "productRatePlanId" => rateplan["id"]}
            charges = {}

            rateplan["productRatePlanCharges"].each do |charge|
              catalog_map[charge["id"]] = {"productId" => product["id"], "productRatePlanId" => rateplan["id"], "productRatePlanChargeId" => charge["id"]}
              charges[charge["id"]] = charge.merge({"productId" => product["id"], "productName" => product["name"], "productRatePlanId" => rateplan["id"], "productRatePlanName" => rateplan["name"] })
            end

            rateplan["productRatePlanCharges"] = charges
            rateplans[rateplan["id"]] = rateplan.merge({"productId" => product["id"], "productName" => product["name"]})
          end
          product["productRatePlans"] = rateplans
          products[product['id']] = product
        end
      end
      return products, catalog_map
    end

    def get_file(url: nil, headers: {}, z_session: true, tempfile: true, output_file_name: nil, zuora_track_id: nil, add_timestamp: true, file_path: defined?(Rails.root.join('tmp')) ? Rails.root.join('tmp') : Pathname.new(Dir.pwd), timeout_retries: 3, timeout: 130, session_type: :basic, **execute_params)
      raise "file_path must be of class Pathname" if file_path.class != Pathname

      retry_count ||= timeout_retries

      #Make sure directory exists
      require 'fileutils'
      FileUtils.mkdir_p(file_path) unless File.exist?(file_path)

      status_code = nil
      uri = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.read_timeout = timeout #Seconds
      http.use_ssl = true  if !uri.scheme.nil? && uri.scheme.downcase == 'https'
      if z_session
        headers = headers.merge({"Authorization" => self.get_session(prefix: true)})

        self.insert_entity_header(headers)
      end

      headers['Zuora-Track-Id'] = zuora_track_id if zuora_track_id.present?
      headers['X-Amzn-Trace-Id'] = zuora_track_id if zuora_track_id.present?
      headers["User-Agent"] = USER_AGENT

      response_save = nil
      http.request_get(uri.request_uri, headers) do |response|
        response_save = response
        status_code = response.code if response
        case response
        when Net::HTTPOK
          headers = {}
          response.each_header do |k,v|
            headers[k] = v
          end
          Rails.logger.debug("Headers: #{headers.to_s}")
          if output_file_name.present?
            file_ending ||= output_file_name.end_with?(".csv.zip") ? ".csv.zip" : File.extname(output_file_name)
            filename ||= File.basename(output_file_name, file_ending)
          end

          size, export_progress = [0, 0]
          encoding, type, full_filename = [nil, nil, nil]
          if response.header["Content-Disposition"].present?
            case response.header["Content-Disposition"]
            when /.*; filename\*=.*/
              full_filename ||= /.*; filename\*=(.*)''(.*)/.match(response.header["Content-Disposition"])[2].strip
              encoding = /.*; filename\*=(.*)''(.*)/.match(response.header["Content-Disposition"])[1].strip
            when /.*; filename=/
              full_filename ||= /.*; filename=(.*)/.match(response.header["Content-Disposition"])[1].strip
            else
              raise "Can't parse Content-Disposition header: #{response.header["Content-Disposition"]}"
            end
            file_ending ||= full_filename.end_with?(".csv.zip") ? ".csv.zip" : File.extname(full_filename)
            filename ||= File.basename(full_filename, file_ending)
          end

          #If user supplied a filename use it, else default to content header filename, else default to uri pattern
          file_ending ||= uri.path.end_with?(".csv.zip") ? ".csv.zip" : File.extname(uri.path)
          filename ||= File.basename(uri.path, file_ending)

          if response.header["Content-Type"].present?
            case response.header["Content-Type"]
            when /.*;charset=.*/
              type = /(.*);charset=(.*)/.match(response.header["Content-Type"])[1]
              encoding = /(.*);charset=(.*)/.match(response.header["Content-Type"])[2]
            else
              type = response.header["Content-Type"]
              encoding ||= 'UTF-8'
            end
          end

          if response.header["Content-Length"].present?
            export_size = response.header["Content-Length"].to_i
          elsif response.header["ContentLength"].present?
            export_size = response.header["ContentLength"].to_i
          end

          Rails.logger.info("File: #{filename}#{file_ending}  #{encoding}  #{type} #{export_size}")

          file_prefix = add_timestamp ? "#{filename}_#{Time.now.to_i}" : filename
          if tempfile
            require 'tempfile'
            file_handle = ::Tempfile.new([file_prefix, "#{file_ending}"], file_path)
          else
            file_handle = File.new(file_path.join("#{file_prefix}#{file_ending}"), "w+")
          end
          file_handle.binmode

          response.read_body do |chunk|
            file_handle << chunk

            if defined?(export_size) && export_size != 0  && export_size.class == Integer
              size += chunk.size
              new_progress = (size * 100) / export_size
              unless new_progress == export_progress
                Rails.logger.debug("Login: Export Downloading %s (%3d%%)" % [filename, new_progress])
              end
              export_progress = new_progress
            end
          end

          file_handle.close
          Rails.logger.debug("Filepath: #{file_handle.path} Size: #{File.size(file_handle.path).to_f/1000000} mb")

          raise ZuoraAPI::Exceptions::ZuoraAPIError.new("Downloaded file is not a file: #{file_handle.class}") if !["Tempfile", "File"].include?(file_handle.class.to_s)
          return file_handle
        when Net::HTTPUnauthorized
          if z_session
            unless (retry_count -= 1).zero?
              self.new_session
              raise ZuoraAPI::Exceptions::ZuoraAPISessionError, 'Retrying'
            end
            raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new(self.current_error)
          end
          raise
        when Net::HTTPNotFound
          if url.include?(self.fileURL)
            raise ZuoraAPI::Exceptions::FileDownloadError.new(
              "The current tenant does not have a file with id '#{url.split('/').last}'"
            )
          else
            raise ZuoraAPI::Exceptions::FileDownloadError.new("File Download Failed #{response.class}")
          end
        else
          raise ZuoraAPI::Exceptions::FileDownloadError.new("File Download Failed #{response.class}")
        end
      end

    rescue => ex
      sleep(5)
      if (retry_count -= 1) >= 0
        retry
      end
      Rails.logger.error("File Download Failed")
      raise
    end

    def getDataSourceExport(query, extract: true, encrypted: false, zip: true, z_track_id: "")
      tries ||= 3

      output_xml, input_xml = self.soap_call(debug: false, timeout_retry: true, zuora_track_id: z_track_id) do |xml|
        xml['ns1'].create do
          xml['ns1'].zObjects('xsi:type' => "ns2:Export") do
            xml['ns2'].Format 'csv'
            xml['ns2'].Zip zip
            xml['ns2'].Name 'googman'
            xml['ns2'].Query query
            xml['ns2'].Encrypted encrypted
          end
        end
      end
      id = output_xml.xpath('//ns1:Id', 'ns1' =>'http://api.zuora.com/').text

      result = 'Waiting'
      while result != "Completed"
        sleep 3
        output_xml, input_xml = self.soap_call(debug: false, timeout_retry: true, zuora_track_id: z_track_id) do |xml|
          xml['ns1'].query do
            xml['ns1'].queryString "SELECT Id, CreatedById, CreatedDate, Encrypted, FileId, Format, Name, Query, Size, Status, StatusReason, UpdatedById, UpdatedDate, Zip From Export where Id = '#{id}'"
          end
        end
        result = output_xml.xpath('//ns2:Status',  'ns2' =>'http://object.api.zuora.com/').text
      end

      file_id = output_xml.xpath('//ns2:FileId',  'ns2' =>'http://object.api.zuora.com/').text
      export_file = get_file(:url => self.fileURL(file_id))
      export_file_path = export_file.path

      if extract && zip
        require "zip"
        new_path = export_file_path.partition('.zip').first
        zipped = Zip::File.open(export_file_path)
        file_handle = zipped.entries.first
        file_handle.extract(new_path)
        File.delete(export_file_path)
        return new_path
      else
        return export_file_path
      end
    rescue ZuoraAPI::Exceptions::ZuoraAPISessionError => ex
      if !(tries -= 1).zero?
        Rails.logger.info("Export call failed - Trace ID: #{z_track_id}")
        self.new_session
        retry
      end
      raise ex

    rescue ZuoraAPI::Exceptions::ZuoraUnexpectedError => ex
      if !(tries -= 1).zero?
        Rails.logger.info("Trace ID: #{z_track_id} UnexpectedError, will retry after 10 seconds")
        sleep(self.timeout_sleep)
        retry
      end
      raise ex
    rescue *(CONNECTION_EXCEPTIONS + CONNECTION_READ_EXCEPTIONS) => ex
      if !(tries -= 1).zero?
        Rails.logger.info("Trace ID: #{z_track_id} Timed out will retry after 5 seconds")
        sleep(self.timeout_sleep)
        retry
      end
      raise ex
    end

    def query(query, parse = false)
      output_xml, input_xml = self.soap_call(debug: false, timeout_retry: true) do |xml|
        xml['ns1'].query do
          xml['ns1'].queryString query
        end
      end
      if parse
        return [] if output_xml.xpath('//ns1:size', 'ns1' =>'http://api.zuora.com/').text == '0'
        data = output_xml.xpath('//ns1:records', 'ns1' =>'http://api.zuora.com/').map {|record| record.children.map {|element| [element.name, element.text]}.to_h}
        return data
      else
        return output_xml
      end
    end

    def createJournalRun(call)
      url = rest_endpoint("/journal-runs")
      uri = URI(url)
      req = Net::HTTP::Post.new(uri,initheader = {'Content-Type' =>'application/json'})
      req["Authorization"] = self.get_session(prefix: true)
      req.body = call

      response = Net::HTTP.start(uri.host, uri.port, :use_ssl => true) do |http|
        http.request req
      end

      Rails.logger.debug("Response #{response.code} #{response.message}: #{response.body}")

      result = JSON.parse(response.body)
      if result["success"]
        jrNumber = result["journalRunNumber"]
        return jrNumber
      else
        message = result["reasons"][0]["message"]
        Rails.logger.error("Journal Run failed with message #{message}")
        return result
      end

    end

    def checkJRStatus(jrNumber)
      Rails.logger.info("Check for completion")
      url = rest_endpoint("/journal-runs/#{jrNumber}")
      uri = URI(url)
      req = Net::HTTP::Get.new(uri,initheader = {'Content-Type' =>'application/json'})
      req["Authorization"] = self.get_session(prefix: true)

      response = Net::HTTP.start(uri.host, uri.port, :use_ssl => true) do |http|
        http.request req
      end

      result = JSON.parse(response.body)
      if result["success"]
        if !(result["status"].eql? "Completed")
          sleep(20.seconds)
        end
        return result["status"]
      else
        message = result["reasons"][0]["message"]
        Rails.logger.info("Checking status of journal run failed with message #{message}")
      end
      return "failure"
    end

    def reset_files(body)
      return unless body.is_a? Hash

      body.transform_values! do |v|
        if v.is_a?(File)
          v.reopen(v.path)
        else
          v
        end
      end
    end
  end
end
