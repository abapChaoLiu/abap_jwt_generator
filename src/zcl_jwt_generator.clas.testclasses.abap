CLASS ltcl_test DEFINITION FINAL
  FOR TESTING
  RISK LEVEL HARMLESS
  DURATION SHORT.

  PUBLIC SECTION.

  PRIVATE SECTION.
    METHODS generate_jwt_with_secret FOR TESTING.

ENDCLASS.

CLASS ltcl_test IMPLEMENTATION.


  METHOD generate_jwt_with_secret.

    DATA:
      BEGIN OF ls_jwt,
        header  TYPE string,
        payload TYPE string,
        secret  TYPE string,
      END OF ls_jwt.

    DATA(lo_jwt_generator) = NEW zcl_jwt_generator( ).

    TRY.
        DATA(lv_jwt) =
            lo_jwt_generator->generate_jwt_with_secret(
                jwt_header = VALUE #( alg = 'HS256' typ = 'JWT' )
                jwt_claim  = VALUE #( sub = '1234567890' name = 'John Doe' iat = lo_jwt_generator->convert_abap_timestamp_to_unix( '20180118013022' ) )
                secret     = '1WRAv0Usf90-jr2W7UQBQBLvIBBFq8vumq-VzrR3h7E'
                algorithm  = 'SHA256' ).
      CATCH zcx_jwt_generator INTO DATA(lx_jwt).
        cl_abap_unit_assert=>fail( msg = lx_jwt->get_text( ) detail = lx_jwt->get_longtext( ) ).
    ENDTRY.

    SPLIT lv_jwt AT '.' INTO ls_jwt-header ls_jwt-payload ls_jwt-secret.

    cl_abap_unit_assert=>assert_equals(
        act = ls_jwt-header
        exp = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        msg = 'Header has invalid content' ).

    cl_abap_unit_assert=>assert_equals(
        act = ls_jwt-payload
        exp = 'eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoiMTUxNjIzOTAyMiJ9'
        msg = 'Payload has invalid content' ).

    cl_abap_unit_assert=>assert_equals(
        act = ls_jwt-secret
        exp = '_GNK9PCjJnoeHZsNx9F-7TnZF8m_jS4lodaNe_w94MM'
        msg = 'Secret has invalid content' ).

  ENDMETHOD.


ENDCLASS.
