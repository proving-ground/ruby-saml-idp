# encoding: utf-8
module SamlIdp
  module Controller
    require 'openssl'
    require 'base64'
    require 'time'
    require 'uuid'

    attr_accessor :x509_certificate, :secret_key, :algorithm
    attr_accessor :saml_acs_url, :saml_request, :saml_request_id, :saml_issuer

    def x509_certificate
      return @x509_certificate if defined?(@x509_certificate)
      @x509_certificate = SamlIdp.config.x509_certificate
    end

    def secret_key
      return @secret_key if defined?(@secret_key)
      @secret_key = SamlIdp.config.secret_key
    end

    def algorithm
      return @algorithm if defined?(@algorithm)
      self.algorithm = SamlIdp.config.algorithm
      @algorithm
    end

    def algorithm=(algorithm)
      @algorithm = algorithm
      if algorithm.is_a?(Symbol)
        @algorithm = case algorithm
        when :sha256 then OpenSSL::Digest::SHA256
        when :sha384 then OpenSSL::Digest::SHA384
        when :sha512 then OpenSSL::Digest::SHA512
        else
          OpenSSL::Digest::SHA1
        end
      end
      @algorithm
    end

    def algorithm_name
      algorithm.to_s.split('::').last.downcase
    end

    protected

      def validate_saml_request(saml_request = params[:SAMLRequest])
        decode_request(saml_request)
      end

      def decode_request(saml_request)
        zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        @saml_request = zstream.inflate(Base64.decode64(saml_request))
        zstream.finish
        zstream.close
        logger.debug "Received request: #{@saml_request}"
        @saml_request_id = @saml_request[/ID=['"](.+?)['"]/, 1]
        logger.debug "SAML Request ID: #{@saml_request_id}"
        @saml_acs_url = @saml_request[/AssertionConsumerServiceURL=['"](.+?)['"]/, 1]
        logger.debug "SAML ACS URL: #{@saml_acs_url}"
        @saml_issuer = @saml_request[/Issuer\>(.+?)\</, 1]
        logger.debug "SAML Issuer: #{@saml_issuer}"
      end

      def encode_response(request_id, request_acs_url, request_issuer_name, opts = {})
        # various time nuggets needed in construction of response
        now = opts[:now] || Time.now.utc
        before_now = opts[:before_now] || now - 5
        after_now = opts[:after_now] || now + 5
        timeout = opts[:timeout] || now + (60*24)

        # The response, assertion and session id's can be more formally stored, but looking to just generate for moment
        response_id, assertion_id, session_id = UUID.generate, UUID.generate, UUID.generate

        # In theory this is from the server store, but will generate random for now
        request_issuer_id = opt[:issuer_id] || UUID.generate

        # This needs to be better defined, but aiming for my needs at moment
        idp_uri = opts[:idp_uri] || (defined?(request) && "https://#{request.host_with_port}/") || "http://idp.example.com/"

        assertion = <<ASSERTION
<saml:Assertion
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:xs="http://www.w3.org/2001/XMLSchema"
	ID="_#{assertion_id}"
	Version="2.0"
	IssueInstant="#{now.iso8601}">
    <saml:Issuer>#{idp_uri}</saml:Issuer>
    <saml:Subject>
      <saml:NameID
	      SPNameQualifier="#{request_issuer_name}"
	      Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_#{request_issuer_id}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData
		      NotOnOrAfter="#{after_now.iso8601}"
		      Recipient="#{request_acs_url}"
		      InResponseTo="#{request_id}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="#{before_now.iso8601}" NotOnOrAfter="#{after_now.iso8601}">
      <saml:AudienceRestriction>
        <saml:Audience>#{request_issuer_name}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement
	    AuthnInstant="#{now.iso8601}"
	    SessionNotOnOrAfter="#{timeout.iso8601}"
	    SessionIndex="_#{session_id}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="firstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">#{opts[:first_name]}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="lastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">#{opts[:last_name]}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">#{opts[:email]}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="externalId" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">#{opts[:account_id]}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
ASSERTION

        signature = create_signature(assertion, assertion_id)
        assertion_and_signature = assertion.sub(/Issuer\>\<Subject/, "Issuer>#{signature}<Subject")

        response = <<RESPONSE
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
	  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
	  ID="_#{response_id}"
    Version="2.0"
    IssueInstant="#{now.iso8601}"
    Destination="#{@saml_acs_url}"
    InResponseTo="#{@saml_request_id}">
  <saml:Issuer>#{idp_uri}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
  </samlp:Status>
  #{assertion_and_signature}
</samlp:Response>
RESPONSE

        signature = create_signature(response, response_id)
        response.sub(/Issuer\>\<Status/, "Issuer>#{signature}<Status")

        logger.debug("SAML Response: #{response}")
        Base64.encode64(response)
      end

    private

    def create_signature(xml_block, reference_id)
      digest_value = Base64.encode64(algorithm.digest(xml_block)).gsub(/\n/, '')

      signed_info = <<SIGNEDINFO
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-#{algorithm_name}"/>
        <ds:Reference URI="_#{reference_id}">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig##{algorithm_name}"/>
          <ds:DigestValue>#{digest_value}</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
SIGNEDINFO

      signature_value = sign(signed_info).gsub(/\n/, '')

      signature = <<SIGNATURE
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      #{signed_info}
      <ds:SignatureValue>#{signature_value}</ds:SignatureValue>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>#{self.x509_certificate}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </ds:Signature>
SIGNATURE

      signature
    end

    def sign(data)
      key = OpenSSL::PKey::RSA.new(self.secret_key)
      Base64.encode64(key.sign(algorithm.new, data))
    end
  end
end