CLASS zcl_jwt_generator DEFINITION
  PUBLIC
  CREATE PUBLIC .

  PUBLIC SECTION.
    TYPES:
      BEGIN OF ty_jwt_header,
        alg TYPE string,
        typ TYPE string,
      END OF ty_jwt_header .
    TYPES:
      BEGIN OF ty_jwt_claim,
        name TYPE string, " Name
        iss  TYPE string, "Issuer
        sub  TYPE string, "Subject
        aud  TYPE string, "Audience
        exp  TYPE string, "Expiration Time
        nbf  TYPE string, "Not Before
        iat  TYPE string, "Issued At
        jti  TYPE string, "JWT ID
      END OF ty_jwt_claim .

    METHODS generate_jwt
      IMPORTING
        !jwt_header       TYPE ty_jwt_header
        !jwt_claim        TYPE ty_jwt_claim
        !ssf_info         TYPE ssfinfo
        !ssf_format       TYPE ssfform DEFAULT 'PKCS1-V1.5'
        !ssf_hash_agrithm TYPE ssfhash DEFAULT 'SHA256'
      RETURNING
        VALUE(jwt)        TYPE string
      RAISING
        zcx_jwt_generator .

    METHODS generate_jwt_with_secret
      IMPORTING
        !jwt_header   TYPE ty_jwt_header
        !jwt_claim    TYPE ty_jwt_claim
        !secret       TYPE string
        !algorithm    TYPE string DEFAULT 'SHA256'
      RETURNING
        VALUE(result) TYPE string
      RAISING
        zcx_jwt_generator .

    METHODS get_jwt_by_profile
      IMPORTING
        !profile   TYPE zjwt_profile-profile_name
      RETURNING
        VALUE(jwt) TYPE string
      RAISING
        zcx_jwt_generator .

    METHODS get_access_token_by_profile
      IMPORTING
        !profile            TYPE zjwt_profile-profile_name
      RETURNING
        VALUE(access_token) TYPE string
      RAISING
        zcx_jwt_generator .

    METHODS base64url_encode
      IMPORTING
        !unencoded       TYPE string
      RETURNING
        VALUE(base64url) TYPE string .

    METHODS convert_abap_timestamp_to_unix
      IMPORTING
        !timestamp    TYPE timestamp
      RETURNING
        VALUE(result) TYPE i .

  PROTECTED SECTION.

  PRIVATE SECTION.
    TYPES:
      ty_tssfbin TYPE STANDARD TABLE OF ssfbin WITH KEY table_line WITHOUT FURTHER SECONDARY KEYS.

    DATA:
      jwt_profile TYPE zjwt_profile.

    METHODS format_jwt_claim
      IMPORTING jwt_claim     TYPE ty_jwt_claim
      RETURNING VALUE(result) TYPE ty_jwt_claim.

    METHODS string_to_binary_tab
      IMPORTING input_string       TYPE string
      RETURNING VALUE(output_bins) TYPE ty_tssfbin
      RAISING   zcx_jwt_generator.

    METHODS binary_tab_to_string
      IMPORTING input_bins           TYPE ty_tssfbin
                length               TYPE ssflen
      RETURNING VALUE(output_string) TYPE string
      RAISING   zcx_jwt_generator.

    METHODS format_base64
      IMPORTING input         TYPE string
      RETURNING VALUE(result) TYPE string.

ENDCLASS.


CLASS zcl_jwt_generator IMPLEMENTATION.


  METHOD base64url_encode.
    base64url = format_base64( cl_http_utility=>encode_base64( unencoded = unencoded ) ).
  ENDMETHOD.


  METHOD binary_tab_to_string.
    CALL FUNCTION 'SCMS_BINARY_TO_STRING'
      EXPORTING
        input_length = length
        encoding     = '4110'
      IMPORTING
        text_buffer  = output_string
      TABLES
        binary_tab   = input_bins
      EXCEPTIONS
        failed       = 1
        OTHERS       = 2.
    IF sy-subrc <> 0.
      zcx_jwt_generator=>raise_system( ).
    ENDIF.
  ENDMETHOD.


  METHOD convert_abap_timestamp_to_unix.

    CONVERT TIME STAMP timestamp TIME ZONE 'UTC' INTO DATE DATA(date) TIME DATA(time).

    cl_pco_utility=>convert_abap_timestamp_to_java(
        EXPORTING
            iv_date = date
            iv_time = time
        IMPORTING
            ev_timestamp = DATA(lv_unix_timestamp) ).

    result =
        COND #(
            WHEN strlen( lv_unix_timestamp ) > 10
                THEN lv_unix_timestamp(10)
                ELSE lv_unix_timestamp ).

  ENDMETHOD.


  METHOD format_base64.

    result = input.

    REPLACE ALL OCCURRENCES OF '=' IN result WITH ''.
    REPLACE ALL OCCURRENCES OF '+' IN result WITH '-'.
    REPLACE ALL OCCURRENCES OF '/' IN result WITH '_'.

  ENDMETHOD.


  METHOD generate_jwt.

    DATA input_bins TYPE STANDARD TABLE OF ssfbin.
    DATA output_bins TYPE STANDARD TABLE OF ssfbin.
    DATA input_length TYPE ssflen.
    DATA output_length TYPE ssflen.
    DATA output_crc TYPE ssfreturn.
    DATA signers TYPE STANDARD TABLE OF ssfinfo.
    DATA: jwt_claim_json       TYPE string,
          jwt_header_json      TYPE string,
          jwt_header_base64url TYPE string,
          jwt_claim_base64url  TYPE string.
    DATA input_base64url TYPE string.
    DATA: signature           TYPE string,
          signature_base64url TYPE string.


    jwt_header_json = /ui2/cl_json=>serialize(
      compress = abap_true
      data  = jwt_header
      pretty_name = /ui2/cl_json=>pretty_mode-low_case    ).

    jwt_claim_json = /ui2/cl_json=>serialize(
      compress = abap_true
      data  = jwt_claim
      pretty_name = /ui2/cl_json=>pretty_mode-low_case  ).


    jwt_header_base64url = base64url_encode( jwt_header_json ).
    jwt_claim_base64url = base64url_encode( jwt_claim_json ).


    input_base64url = |{ jwt_header_base64url }.{ jwt_claim_base64url }|.
    input_length = strlen( input_base64url ).

    input_bins = string_to_binary_tab( input_string = input_base64url ).


    APPEND ssf_info TO signers.

    CALL FUNCTION 'SSF_KRN_SIGN'
      EXPORTING
        str_format                   = ssf_format
        b_inc_certs                  = abap_false
        b_detached                   = abap_false
        b_inenc                      = abap_false
        ostr_input_data_l            = input_length
        str_hashalg                  = ssf_hash_agrithm
      IMPORTING
        ostr_signed_data_l           = output_length
        crc                          = output_crc    " SSF Return code
      TABLES
        ostr_input_data              = input_bins
        signer                       = signers
        ostr_signed_data             = output_bins
      EXCEPTIONS
        ssf_krn_error                = 1
        ssf_krn_noop                 = 2
        ssf_krn_nomemory             = 3
        ssf_krn_opinv                = 4
        ssf_krn_nossflib             = 5
        ssf_krn_signer_list_error    = 6
        ssf_krn_input_data_error     = 7
        ssf_krn_invalid_par          = 8
        ssf_krn_invalid_parlen       = 9
        ssf_fb_input_parameter_error = 10.
    IF sy-subrc <> 0.
      zcx_jwt_generator=>raise_system( ).
    ENDIF.

    signature = binary_tab_to_string( input_bins = output_bins
                                      length  = output_length ).

    signature_base64url = base64url_encode( signature ).

    jwt = |{ input_base64url }.{ signature_base64url }|.

  ENDMETHOD.


  METHOD generate_jwt_with_secret.

    DATA(header_json) =
        /ui2/cl_json=>serialize(
            data        = jwt_header
            compress    = abap_true
            pretty_name = /ui2/cl_json=>pretty_mode-low_case ).

    DATA(header_base64) = base64url_encode( header_json ).

    DATA(payload_json) =
        /ui2/cl_json=>serialize(
            data        = format_jwt_claim( jwt_claim )
            compress    = abap_true
            pretty_name = /ui2/cl_json=>pretty_mode-low_case ).

    DATA(payload_base64) = base64url_encode( payload_json ).

    DATA(data_to_sign) =
        |{ header_base64 }.{ payload_base64 }|.

    TRY.
        cl_abap_hmac=>calculate_hmac_for_char(
           EXPORTING
             if_algorithm     = algorithm
             if_key           = cl_abap_hmac=>string_to_xstring( secret )
             if_data          = data_to_sign
           IMPORTING
             ef_hmacb64string = DATA(hmacb64string) ).
      CATCH cx_abap_message_digest INTO DATA(lx_message_digest).
        RAISE EXCEPTION TYPE zcx_jwt_generator
          EXPORTING
            previous = lx_message_digest.
    ENDTRY.

    DATA(lv_signature) = format_base64( hmacb64string ).

    result =
        |{ header_base64 }.{ payload_base64 }.{ lv_signature }|.

  ENDMETHOD.


  METHOD get_access_token_by_profile.

    DATA:
      BEGIN OF ls_token,
        access_token TYPE string,
      END OF ls_token.
    DATA:
      lo_client TYPE REF TO if_http_client,
      jwt       TYPE string.
    FIELD-SYMBOLS:
      <data>         TYPE data,
      <access_token> TYPE data.

    jwt = get_jwt_by_profile( profile = profile ).

    cl_http_client=>create_by_url(
      EXPORTING
        url                = jwt_profile-aud    " URL
        ssl_id             = 'ANONYM'    " SSL Identity
      IMPORTING
        client             = lo_client   " HTTP Client Abstraction
      EXCEPTIONS
        argument_not_found = 1
        plugin_not_active  = 2
        internal_error     = 3
        OTHERS             = 4 ).
    IF sy-subrc <> 0.
      zcx_jwt_generator=>raise_system( ).
    ENDIF.


    IF lo_client IS NOT BOUND.
      zcx_jwt_generator=>raise_system( ).
    ENDIF.

    lo_client->request->set_method( if_http_request=>co_request_method_post ).
    lo_client->request->set_formfield_encoding( formfield_encoding = if_http_entity=>co_formfield_encoding_encoded ).

    lo_client->request->set_header_field(
        name  =  'Content-type'   " Name of the header field
        value =  'application/x-www-form-urlencoded' ).   " HTTP header field value

    lo_client->request->set_form_field(
        name  = 'grant_type'
        value = 'urn:ietf:params:oauth:grant-type:jwt-bearer' ).

    lo_client->request->set_form_field(
        name  = 'assertion'
        value = jwt ).

    lo_client->send( ).
    lo_client->receive(
      EXCEPTIONS
        http_communication_failure = 1
        http_invalid_state         = 2
        http_processing_failed     = 3 ).
    IF sy-subrc <> 0.
      zcx_jwt_generator=>raise_system( ).
    ENDIF.

    DATA(response_json) = lo_client->response->get_cdata( ).

    lo_client->close( ).
    IF sy-subrc <> 0.
      zcx_jwt_generator=>raise_system( ).
    ENDIF.

    /ui2/cl_json=>deserialize(
      EXPORTING
        json = response_json
      CHANGING
        data = ls_token ).

    access_token = ls_token-access_token.

  ENDMETHOD.


  METHOD get_jwt_by_profile.

    DATA: jwt_header TYPE ty_jwt_header,
          jwt_claim  TYPE ty_jwt_claim.

    DATA: current_timestamp TYPE timestamp,
          exp_timestamp     TYPE tzntstmpl,
          diff_second       TYPE tzntstmpl,
          exp_second        TYPE int8,
          ssfinfo           TYPE ssfinfo.
    CONSTANTS: start_timestamp TYPE timestamp VALUE '19700101000000'.

    SELECT SINGLE * FROM zjwt_profile INTO jwt_profile
           WHERE profile_name =  profile.
    IF sy-subrc = 0.
      GET TIME STAMP FIELD current_timestamp.
      cl_abap_tstmp=>add(
        EXPORTING
          tstmp                      =  current_timestamp   " UTC Time Stamp
          secs                       =  jwt_profile-time_interval   " Time Interval in Seconds
        RECEIVING
          r_tstmp                    =  exp_timestamp   ). " UTC Time Stamp
      cl_abap_tstmp=>subtract(
        EXPORTING
          tstmp1                     =  exp_timestamp   " UTC Time Stamp
          tstmp2                     =  start_timestamp   " UTC Time Stamp
        RECEIVING
          r_secs                     =  diff_second  ). " Time Interval in Seconds


      MOVE-CORRESPONDING jwt_profile TO jwt_claim.
      exp_second = diff_second.
      jwt_claim-exp = exp_second.

      ssfinfo-id = jwt_profile-ssf_id.
      ssfinfo-profile = jwt_profile-ssf_profile.
      jwt_header-alg = jwt_profile-alg.

      generate_jwt(
         EXPORTING
           jwt_header     = jwt_header
           jwt_claim      = jwt_claim
           ssf_info       = ssfinfo
         RECEIVING
           jwt            = jwt ).

    ELSE.
      "TO DO
      zcx_jwt_generator=>raise_system( ).
    ENDIF.

  ENDMETHOD.


  METHOD format_jwt_claim.

    result = jwt_claim.

    result-iat = condense( result-iat ).
    result-exp = condense( result-exp ).

  ENDMETHOD.


  METHOD string_to_binary_tab.
    DATA lv_xstring TYPE xstring.

    CALL FUNCTION 'SCMS_STRING_TO_XSTRING'
      EXPORTING
        text     = input_string
        encoding = '4110'
      IMPORTING
        buffer   = lv_xstring
      EXCEPTIONS
        failed   = 1
        OTHERS   = 2.
    IF sy-subrc <> 0.
      zcx_jwt_generator=>raise_system( ).
    ENDIF.

    CALL FUNCTION 'SCMS_XSTRING_TO_BINARY'
      EXPORTING
        buffer     = lv_xstring
      TABLES
        binary_tab = output_bins.
    IF sy-subrc <> 0.
      zcx_jwt_generator=>raise_system( ).
    ENDIF.
  ENDMETHOD.
ENDCLASS.
