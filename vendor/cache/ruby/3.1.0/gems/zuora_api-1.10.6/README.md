# Zuora Gem

[![Gem Version](https://badge.fury.io/rb/zuora_api.svg)](https://badge.fury.io/rb/zuora_api) [![coverage report](https://gitlab.0.ecc.auw2.zuora/extension-products/shared-libraries/zuora-gem/badges/master/coverage.svg)](https://gitlab.0.ecc.auw2.zuora/extension-products/shared-libraries/zuora-gem/commits/master)

## Installation
Add this line to your application's Gemfile:

```ruby
gem 'zuora_api'
```
Then execute `bundle install` in your terminal

## Usage

### Zuora Login Object
In order to make API calls a Zuora Login object must be created

```ruby
zuora_client = ZuoraAPI::Login.new(username: "username", password: "password", url: "url")
```

|        Name         |    Type     |                                       Description                                        |                                                                       Example                                                                       |
| ------------------- | ----------- | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| username            | `Attribute` | Username to the Zuora environment                                                        | `zuora_client.username = "username"`                                                                                                                |
| password            | `Attribute` | password to the Zuora environment                                                        | `zuora_client.password = "Password"`                                                                                                                |
| url                 | `Attribute` | Endpoint to the Zuora tenant                                                             | `zuora_client.url = "www.zuora.com"`                                                                                                                |
| wsdl_number         | `Attribute` | WSDL number of the zuora login                                                           | `wsdl = zuora_client.wsdl_number`                                                                                                                   |
| status              | `Attribute` | Status of the login                                                                      | `zuora_client.status`                                                                                                                               |
| current_session     | `Attribute` | Current session for the login                                                            | `zuora_client.current_session`                                                                                                                      |
| environment         | `Attribute` | environment of the login                                                                 | `zuora_client.environment`                                                                                                                          |
| errors              | `Attribute` | Any errors that the login has based on the login call                                    | `zuora_client.errors`                                                                                                                               |
| current_error       | `Attribute` | Current error from the new_session call                                                  | `zuora_client.current_error`                                                                                                                        |
| user_info           | `Attribute` | Information related to the login                                                         | `zuora_client.user_info`                                                                                                                            |
| tenant_id           | `Attribute` | Tenant ID the login is associated to                                                     | `zuora_client.tenant_id`                                                                                                                            |
| tenant_name         | `Attribute` | Tenant Name of tenant the login is associated to                                         | `zuora_client.tenant_name`                                                                                                                          |
| entity_id           | `Attribute` | Current entity the login session is associated to                                        | `zuora_client.entity_id`                                                                                                                            |
| rest_call           | `Method`    | Executes a REST call                                                                     | `zuora_client.rest_call()`                                                                                                                          |
| soap_call           | `Method`    | Executes a SOAP call                                                                     | `output_xml, input_xml = zuora_client.soap_call() do `&#124;xml, args&#124;` xml['ns1'].query do xml['ns1'].queryString "select id, name from account" end end` |
| query               | `Method`    | Executes a query call                                                                    | `zuora_client.query("select id, name from account")`                                                                                                |
| getDataSourceExport | `Method`    | Pulls a data source export with the given query and returns the file location            | `zuora_client.getDataSourceExport("select id, name from account")`                                                                                  |
| describe_call       | `Method`    | Performs the describe call against the Zuora tenant for all objects or a specific object | `response = zuora_client.describe_call("Account")`                                                                                                  |
| createJournalRun    | `Method`    | Creates a Journal Run                                                                    | `zuora_client.createJournalRun(call)`                                                                                                               |
| checkJRStatus       | `Method`    | Checks the status of a journal run                                                       | `zuora_client.checkJRStatus(journal_run_id)`                                                                                                        |
| update_environment  | `Method`    | Sets the login's environment based on the url                                            | `zuora_client.update_environment`                                                                                                                   |
| aqua_endpoint       | `Method`    | Returns the AQuA endpoint for the login based off the environment                        | `zuora_client.aqua_endpoint`                                                                                                                        |
| rest_endpoint       | `Method`    | Returns the REST endpoint for the login based off the environment                        | `zuora_client.rest_endpoint`                                                                                                                          |
| fileURL             | `Method`    | Returns the URL for files                                                                | `zuora_client.fileURL`                                                                                                                                |
| dateFormat          | `Method`    | Returns the data format syntax based on the wsdl_number                                  | `zuora_client.dateFormat`                                                                                                                             |
| new_session         | `Method`    | Create a new session                                                                     | `zuora_client.new_session`                                                                                                                          |
| get_session         | `Method`    | Returns the current session                                                              | `zuora_client.get_session`|

## Rest Call
```ruby
zuora_client.rest_call(method: :get, body: {}, url: zuora_client.rest_endpoint("catalog/products?pageSize=4"))
```

### Soap Call
Returns both output and input XML

```ruby
zuora_client.soap_call(ns1: 'ns1', ns2: 'ns2', batch_size: nil, single_transaction: false)
```

Example Call

```ruby
output_xml, input_xml = zuora_client.soap_call() do |xml, args|
 xml['ns1'].query do
  xml['ns1'].queryString "select id, name from account"
 end
end
```
### Query
```ruby
zuora_client.query("select id from account")
```
### Data Export
Returns the file location of the data source export after downloading from Zuora

```ruby
zuora_client.getDataSourceExport("select id from account")
```

|   Name    |                              Description                               | Default |                                    Example                                    |
| --------- | ---------------------------------------------------------------------- | ------- | ----------------------------------------------------------------------------- |
| query     | The query to execute                                                   | `N/A`   | `zuora_client.getDataSourceExport("select id from account")`                  |
| zip       | Indicates if the data source export should be a zip                    | `true`  | `zuora_client.getDataSourceExport("select id from account", zip: false)`      |
| extract   | Indicates if the data source export should be extracted if it is a zip | `true`  | `zuora_client.getDataSourceExport("select id from account", extract: false)`  |
| encrypted | Indicates if the data source export should be encrypted                | `false` | `zuora_client.getDataSourceExport("select id from account", encrypted: true)` |

### Describe Call
This returns all available objects from the describe call as a hash. This response can be accessed by using response["Account"] to retrieve all related data about that object.

```ruby
response = zuora_client.describe_call("Account")
```
This returns all information and fields related to that object model as a hash.

```ruby
response = zuora_client.describe_call()
```

### Journal Run
```ruby
zuora_client.createJournalRun(call)
```

## Insights API

In order to make API calls a Zuora Login object must be created by running:

```ruby
insightsapi = InsightsAPI::Login.new(api_token: "api token", url: "Nw1.api.insights.zuora.com/api/")
```

Note that the login will default to the insights production url.

```ruby
Date format: "YYYY-MM-DDT00:00:00Z"
```

### Uploading Data into Insights
```ruby
insightsapi.upload_into_insights(dataSourceName, recordType, batchDate, filePath)
```
dataSourceName: What system the data is coming from.
recordType: The type of records ie: "EVENTS, ATTRIBUTES, and METRICS"
batachDate: The date the data applies to.

### Describing Insights Data
```ruby
insightsapi.describe(type: "ACCOUNT/USER", object: "ATTRIBUTES/EVENTS/SEGMENTS/METRICS")
```
Returns json payload describing attributes, events, metrics for each Account or User.

### Downloading Data from Insights
```ruby
insightsapi.data_export_insights(objecttype, segmentuuid, startDate: nil, endDate: nil, tries: 30)
```
```ruby
insightsapi.data_export_insights_file(objecttype, segmentuuid, startDate: nil, endDate: nil, tries: 30)
```
Both do the same thing except one returns a url(data_export_insights) to download the file yourself and the other returns an actual Ruby temporary file(data_export_insights_file).

objectype: "ACCOUNT/USER"

segmentuuid: A single or array of string or int of a segment uuid(s) that you get from the describe call. The csv holds a column with a bool that represents if that User or Account belongs to that segment.

### License Information
IN THE EVENT YOU ARE AN EXISTING ZUORA CUSTOMER, USE OF THIS SOFTWARE IS GOVERNEDBY THE MIT LICENSE SET FORTH BELOW AND NOT THE MASTER SUBSCRIPTION AGREEMENT OR OTHER COMMERCIAL AGREEMENT ENTERED INTO BETWEEN YOU AND ZUORA (“AGREEMENT”). FOR THE AVOIDANCE OF DOUBT, ZUORA’S OBLIGATIONS WITH RESPECT TO TECHNICAL SUPPORT, UPTIME, INDEMNIFICATION, AND SECURITY SET FORTH IN THE AGREEMENT DO NOT APPLY TO THE USE OF THIS SOFTWARE.

Copyright 2021 Zuora, Inc.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
