require "base64"
require "securerandom"
require "openssl"
require "nokogiri"

# Constants
C14N    = Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
NS_MAP  = {
  "c14n"  => "http://www.w3.org/2001/10/xml-exc-c14n#",
  "ds"    => "http://www.w3.org/2000/09/xmldsig#",
  "saml"  => "urn:oasis:names:tc:SAML:2.0:assertion",
  "samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
  "md"    => "urn:oasis:names:tc:SAML:2.0:metadata",
  "xsi"   => "http://www.w3.org/2001/XMLSchema-instance",
  "xs"    => "http://www.w3.org/2001/XMLSchema"
}

SHA_MAP = {
  1    => OpenSSL::Digest::SHA1,
  256  => OpenSSL::Digest::SHA256,
  384  => OpenSSL::Digest::SHA384,
  512  => OpenSSL::Digest::SHA512
}

class SamlController < ApplicationController

skip_before_filter :verify_authenticity_token

	def acs
		samlResponse = SAMLResponse.new
		strCleanResponse = samlResponse.ParseSAMLResponse(params[:SAMLResponse])
		xDoc = Nokogiri::XML(strCleanResponse)
		
		if samlResponse.IsResponseValid?(xDoc)
			@greeting = "SAML Response from IDP Was Accepted. Authenticated user is " + samlResponse.ParseNameId(xDoc)
		else
			@greeting = "SAML Response from IDP Was Not Accepted"
		end
	end

	def default
		newRequest = SAMLRequest.new
		base64request = newRequest.GetSAMLRequest("http://localhost:3000/saml/acs", "https://cloud.centrify.com/SAML/GenericSAML")
		redirect_to generate_url("https://aaa3021.my-kibble.centrify.com/applogin/appKey/ac53efff-d0e4-4532-9faf-547bafc1a1f7/customerId/AAA3021", :SAMLRequest => base64request)
	end
  
	def generate_url(url, params = {})
		uri = URI(url)
		uri.query = params.to_query
		uri.to_s
	end
end

class SAMLRequest
	def GetSAMLRequest(strACSUrl, strIssuer)
		builder = Nokogiri::XML::Builder.new do |xml|
          xml.AuthnRequest("xmlns:samlp" => NS_MAP["samlp"], "xmlns:saml" => NS_MAP["saml"], "ID" => "_" + SecureRandom.uuid, "IssueInstant" => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ"), "Version" => "2.0") do
            xml.doc.root.namespace = xml.doc.root.namespace_definitions.find { |ns| ns.prefix == "samlp" }
			
			xml.doc.root["AssertionConsumerServiceURL"] = strACSUrl
			xml["saml"].Issuer(strIssuer)
			xml["samlp"].NameIDPolicy("AllowCreate" => "true", "Format" => "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified")
			xml["samlp"].RequestedAuthnContext("Comparison" => "exact") do
                xml["saml"].AuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
              end
			end
		end
		
		base64_request = Base64.encode64(builder.to_xml(:save_with => Nokogiri::XML::Node::SaveOptions::AS_XML | Nokogiri::XML::Node::SaveOptions::NO_DECLARATION).strip)
		
		return base64_request
	end
end

class SAMLResponse
	def ParseSAMLResponse(saml)       
        strCleanResponse = Base64.decode64(saml)
        begin
          inflate(strCleanResponse)
        rescue
          strCleanResponse
        end
     end
	 
	 def IsResponseValid?(xDoc)		 
		# Set up the certificate
		certificate = OpenSSL::X509::Certificate.new(File.read("SignCertFromCentrify.cer"))

		# Read the document
		original = xDoc
		document = original.dup
		prefix = "/samlp:Response"

		# Read, then clear,  the signature
		signature = document.at("#{prefix}/ds:Signature", NS_MAP)
		signature.remove

		# Verify the document digests to ensure that the document hasn't been modified
		original.xpath("#{prefix}/ds:Signature/ds:SignedInfo/ds:Reference[@URI]", NS_MAP).each do |ref|
			digest_value = ref.at("./ds:DigestValue", NS_MAP).text
			decoded_digest_value = Base64.decode64(digest_value);
  
			reference_id = ref["URI"][1..-1]
			reference_node = document.xpath("//*[@ID='#{reference_id}']").first
			reference_canoned = reference_node.canonicalize(C14N)

			# Figure out which method has been used to the sign the node
			digest_method = OpenSSL::Digest::SHA1
			if ref.at("./ds:DigestMethod/@Algorithm", NS_MAP).text =~ /sha(\d+)$/
				digest_method = SHA_MAP[$1.to_i]
			end

			# Verify the digest
			digest = digest_method.digest(reference_canoned)
			if digest == decoded_digest_value
				print "Digest verified for #{reference_id}\n"
			else
				print "Digest check mismatch for #{reference_id}\n"
			end
		end

		# Canonicalization: Stringify the node in a nice way
		node = original.at("#{prefix}/ds:Signature/ds:SignedInfo", NS_MAP)
		canoned = node.canonicalize(C14N)

		# Figure out which method has been used to the sign the node
		signature_method = OpenSSL::Digest::SHA1
		if signature.at("./ds:SignedInfo/ds:SignatureMethod/@Algorithm", NS_MAP).text =~ /sha(\d+)$/
			signature_method = SHA_MAP[$1.to_i]
		end

		# Read the signature
		signature_value = signature.at("./ds:SignatureValue", NS_MAP).text
		decoded_signature_value = Base64.decode64(signature_value);

		# Finally, verify that the signature is correct
		verify = certificate.public_key.verify(signature_method.new, decoded_signature_value, canoned)
		if verify
			return true
		else
			return false
		end
	 end
	 
	 def ParseNameId(xDoc)
		assertionNode = xDoc.at("/samlp:Response/saml:Assertion", NS_MAP)
		nameIdNode = assertion.at("./saml:Subject/saml:NameID", NS_MAP)
		
		return nameIdNode.text		
	 end
end

