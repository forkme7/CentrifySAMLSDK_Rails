# CentrifySAMLSDK_Rails

This is an example on adding SAML to your Ruby on Rails web application. To use this demo you will need a Signing Certificate from a Centrify Generic SAML Application, and the endpoint URL's from the Centrify Generic SAML Application.

To use this example:

In the Centrify Cloud Manager, click on Apps, New App, Custom, Generic SAML Application.

In the Centrify Cloud Manager, in the Generic SAML Application settings, click Download Certificate under Application Settings.

In the Centrify Cloud Manager, in the Generic SAML Application settings, copy the Identity Provider URL under Application Settings.

In your Ruby IDE, remove the sample Signing Certificate in the root directory and replace it with the Certificate downloaded from the Generic SAML Application.

In Visual Studio, modify the SAML_Interface.cs file at line 35 (cSigningCertificate.Import(HttpContext.Current.Server.MapPath(".") + @"\Certificates\SignCertFromCentrify.cer");) and make the path to the cert file point to your file downloaded from Centrify.

In your Ruby IDE, modify the saml_controller.rb file with your applications issuer and IdentityProviderSigninURL from the Generic SAML Application.

In the Centrify Cloud Manager, in the Generic SAML Application settings, make the ACS URL the URL to your localhost and the ACS.aspx page (example would be http://localhost:3000/saml/acs).

In the Centrify Cloud Manager, deploy the Generic SAML Application.

Start your rails server (ruby bin/rails server). If you navigate to http://localhost:3000, you will start SP Initiated SAML SSO. If you go the User Portal and click the Generic SAML Application you will start IDP Initiated SAML SSO.
