![abapLint](https://github.com/abapChaoLiu/abap_jwt_generator/workflows/abapLint/badge.svg?branch=master)

# ABAP JWT Generator
Generate Json Web Token (JWT) in ABAP.

## Demo 1 - method get_jwt_by_profile().

If JWT profile is maintained in table ZJWT_PROFILE, use method get_jwt_by_profile() to derive JWT token by profile name.

![JWT profile screenshot](/doc/jwt_profile.png)

```abap
DATA: jwt_generator TYPE REF TO zcl_jwt_generator,
      jwt TYPE string.

CREATE OBJECT jwt_client.
jwt = jwt_client->get_jwt_by_profile( 'JWT_PROFILE_NAME' ).
```      

## Demo 2 - method generate_jwt().
If JWT profile is not maintained, use method generate_jwt() to derive JWT token.

```abap
REPORT zrpt_jwt_generator_demo.

DATA: jwt_generator TYPE REF TO zcl_jwt_generator.
DATA: jwt_header TYPE zcl_jwt_generator=>ty_jwt_header,
      jwt_claim  TYPE zcl_jwt_generator=>ty_jwt_claim.
DATA: exp_second        TYPE int8,
      ssf_info           TYPE ssfinfo.
DATA: start_timestamp TYPE timestamp VALUE '19700101000000',
      ssf_id          TYPE ssfid VALUE '<implicit>',
      "PSE profile with private key
      ssf_profile     TYPE ssfprof VALUE 'SAPZJWTSF001.pse'.


jwt_header-alg  = 'RS256'.
jwt_claim = VALUE #(  iss = 'UserID'
                      sub = 'example@gmail.com'
                      aud = 'https://login.example.com'
                      exp = exp_second ).

ssf_info = VALUE #( id = ssf_id profile = ssf_profile ).

CREATE OBJECT jwt_generator.
TRY.
    jwt_generator->generate_jwt(
      EXPORTING
        jwt_header     = jwt_header
        jwt_claim      = jwt_claim
        ssf_info       = ssfinfo
      RECEIVING
        jwt            = DATA(jwt) ).
  CATCH zcx_jwt_generator INTO DATA(lo_exp).
    WRITE /: 'ERROR when generate JWT token.'.
    WRITE /: lo_exp->get_text( ).
ENDTRY.
```

## Demo 3 - method get_access_token_by_profile().

If JWT profile is maintained in table ZJWT_PROFILE, use method get_access_token_by_profile() to get JWT Access Token.

![JWT profile screenshot](/doc/jwt_profile.png)

```abap
DATA: jwt_generator TYPE REF TO zcl_jwt_generator,
      jwt_access_token TYPE string.

CREATE OBJECT jwt_client.
jwt_access_token = jwt_client->get_access_token_by_profile( 'JWT_PROFILE_NAME' ).
```

## Demo 4 - method generate_jwt_with_secret().
You can use method generate_jwt_with_secret() to generate a JWT with the secret key, like [JWT Debugger](https://jwt.io/#debugger-io).
```abap
GET TIME STAMP FIELD DATA(timestamp).

DATA(jwt_generator) = NEW zcl_jwt_generator( ).

TRY.
    DATA(jwt_result) =
        jwt_generator->generate_jwt_with_secret(
            jwt_header = VALUE #( alg  = 'HS256' typ = 'JWT' )
            jwt_claim  = VALUE #( sub  = '1234567890'
                                  name = 'John Doe'
                                  iat  = jwt_generator->convert_abap_timestamp_to_unix( timestamp ) )
            secret     = '1WRAv0Usf90-jr2W7UQBQBLvIBBFq8vumq-VzrR3h7E'
            algorithm  = 'SHA256' ).
  CATCH zcx_jwt_generator INTO DATA(lx_jwt).
ENDTRY.
```

## Credits and references

Class ZCL_JWT_Generator is modified from Dimitri Seifmann's post [Connect from AS ABAP to Google Cloud Platform App-Engine resource secured with Google Identity-Aware Proxy](https://blogs.sap.com/2019/11/10/connect-from-as-abap-to-google-cloud-platform-app-engine-resource-secured-with-google-identity-aware-proxy/).
