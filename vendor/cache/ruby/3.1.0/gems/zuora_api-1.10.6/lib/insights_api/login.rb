require "httparty"
module InsightsAPI
  class Login
    attr_accessor :api_token, :url

    def initialize(api_token: nil, url: nil, **keyword_args)
      @api_token = api_token
      @url = url
      @status = "Active"
    end

    def insight_getstatus(uuid)
      response = HTTParty.get(
              "https://#{@url}/export/status/#{uuid}",
              :basic_auth => { :username => @api_token })
      if response.code == 200
        parsed = JSON.parse(response.body)
        return parsed
      #error handing here
      end
    end

    def data_export_insights_file(objecttype, segmentuuid, startDate, endDate, tries: 30)
      status = data_export_insights(objecttype, segmentuuid, startDate, endDate, tries: tries)
      if status['status']== "COMPLETE"
        signedUrl = status['signedUrl']
        return get_file(file_name: "insights-#{startDate}-#{endDate}.csv", url: signedUrl, headers: {}, count: 3, file_type: "zip")
      else
        return status
      end
    end

    def data_export_insights(objecttype, segmentuuid, startDate, endDate, tries: 30)
      status = insights_fetch_all(objecttype, segmentuuid, startDate, endDate)
      if status['uuid'] == nil
        return "Failed: #{status["response"]}"
      else
        fileid = status['uuid']
      end
      for retries in 1..tries
        status = insight_getstatus(fileid)
        if status['status']== "COMPLETE"
          signedUrl = status['signedUrl']
          return status
        elsif status['status'] == "FAILED" || status['status'] == "ERROR"
          return status
        else
          sleep(60)
          retries+=1
        end
        if retries > tries - 1
          return "Timeout"
        end
      end
      return signedUrl
    end

    def insights_fetch_all(objecttype, segmentuuid, startDate, endDate)
      if segmentuuid.is_a? Array
        segmentsForAPI = segmentuuid.join('","')
      elsif segmentuuid.is_a? String
        segmentsForAPI = segmentuuid
      elsif segmentuuid.is_a? Integer
        segmentsForAPI = segmentuuid.to_s
      else
        raise "Error fetching Insights data: Segmentuuid must be either an array of uuids or an single uuid in string or interger format."
      end

      response = HTTParty.post(
              "https://#{@url}/export/type/#{objecttype}",
              :basic_auth => { :username => @api_token },
              :headers => {'Content-Type'=> "Application/json"},
              :body =>
              '
              {
                "endDate": "' + (dateFormat(date: endDate)).to_s + '",
                "startDate":"' + (dateFormat(date: startDate)).to_s + '",
                "segments": [
                  "'+segmentsForAPI+'"
                ]
              }
              ')
      if response.code == 200
        parsed = JSON.parse(response.body)
        return parsed
      else
        return {"uuid"=> nil, "status"=>"Error", "signedUrl"=>"signedUrl", "response" => response.body}
      end
    end

    def dateFormat(date: nil)
      date ||= DateTime.now
      if date.is_a? String
        if date.include? "T"
          return (date.to_datetime).to_s
        else
          return (date.to_date).to_s + "T#{DateTime.now.to_s(:time)}:00Z"
        end
      elsif date.instance_of?(DateTime)
        return date.to_s
      elsif date.instance_of?(Date)
        return (date.to_date).to_s + "T#{DateTime.now.to_s(:time)}:00Z"
      else
        raise "Please pass in a in format of 'YYYY-MM-DD', 'YYYY-MM-DDT00:00:00+00:00' ruby Date, or ruby DateTime"
      end
    end

    def upload_into_insights(dataSourceName, recordType, batchDate, filePath)
      begin
        temp_date = dateFormat(date: batchDate)
        response = HTTParty.post(
          "https://#{@url}/files/upload",
          :basic_auth => { :username => @api_token }, :body => {
          :dataSource => dataSourceName, :recordType => recordType,
          :batchDate => temp_date})
        parsed = JSON.parse(response.body)
        signedUrl = parsed['signedUrl']
        if !File.extname(filePath) == ".gz"
          zipPath = gzip_file(filePath)
        else
          zipPath = filePath
        end

        gzippedFile = File.open(zipPath)
        post = HTTParty.put(signedUrl,
          :body => gzippedFile.read)
        if post.code == 200
          return {"status"=>"COMPLETE", "signedUrl"=>"#{signedUrl}", "response" => post.code, "batchDate" => "#{temp_date}"}
        else
          return {"status"=>"Error", "signedUrl"=>"#{signedUrl}", "response" => post.code, "message"=> "#{post.message}", "batchDate" => "#{temp_date}"}
        end
      rescue Exception => e
          Rails.logger.debug "[ZuoraGem]: While uploading to insights Error: #{e}"
        raise e
      end
    end

    def describe(type: "ACCOUNT", object: "attributes")
      url = "https://#{@url}/export/#{object}/#{type}"
      uri = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      begin
        request = Net::HTTP::Get.new(uri.request_uri)
        request.basic_auth(@api_token, "")
        return http.request(request)
      rescue Exception => e
        Rails.logger.debug "[ZuoraGem]: While describing Zoura Insights objects: #{e}"
        return "Failed"
      end
    end

    def get_file(file_name: nil, url: nil,  basic: {:username => nil, :password => nil}, headers: {}, count: 3, file_type: "zip")
      tries ||= 2
      temp_file = nil
      uri = URI(url)
      Net::HTTP.start(uri.host, uri.port, :use_ssl => uri.scheme == 'https') do |http|
        request = Net::HTTP::Get.new(uri)
        headers.each do |k,v|
          request["#{k}"] = v
        end
        request.basic_auth(basic[:username], basic[:password]) if (!basic[:username].blank? && !basic[:password].blank?)
        http.request request do |response|
          case response
          when Net::HTTPNotFound
            Rails.logger.fatal("[ZuoraGem]: 404 - Not Found")
            raise response

          when Net::HTTPUnauthorized
            raise ZuoraAPI::Exceptions::ZuoraAPISessionError.new(zuora_client.current_error) if count <= 0
            Rails.logger.fatal("[ZuoraGem]: Retry")
            zuora_client.new_session
            return get_file(:url => url, :count => count - 1, :headers => headers)

          when Net::HTTPClientError
            Rails.logger.debug("[ZuoraGem]: #{response}")
            raise response

          when Net::HTTPOK
            Tempfile.open([file_name.rpartition('.').first, ".#{file_name.rpartition('.').last}"], "#{Rails.root}/tmp") do |tmp_file|
              temp_file ||= tmp_file
              tmp_file.binmode if (response.to_hash["content-type"].include?("application/zip") || response.to_hash["content-type"] == "application/zip")
              response.read_body do |chunk|
                tmp_file.write chunk.force_encoding("UTF-8")
              end
            end
          end
        end
      end

      rescue => ex
        raise ex if tries.zero?

        tries -= 1
        sleep 3
        retry
      else
        return temp_file
    end

    def gzip_file(filePath)
      require "zip"
      Zlib::GzipWriter.open(filePath + ".gz") do |gzip|
         open(filePath, "rb") do |f|
            f.each_chunk() {|chunk| gzip.write chunk }
          end
        gzip.close
      end
      return filePath+ ".gz"
    end

  end
end

class File
  def each_chunk(chunk_size=2**16)
      yield read(chunk_size) until eof?
  end
end
