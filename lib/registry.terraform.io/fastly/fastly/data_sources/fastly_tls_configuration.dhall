{ Type =
    { created_at : Optional Text
    , default : Optional Bool
    , dns_records :
        Optional
          (List { record_type : Text, record_value : Text, region : Text })
    , http_protocols : Optional (List Text)
    , id : Optional Text
    , name : Optional Text
    , tls_protocols : Optional (List Text)
    , tls_service : Optional Text
    , updated_at : Optional Text
    }
, default =
  { created_at = None Text
  , default = None Bool
  , dns_records =
      None (List { record_type : Text, record_value : Text, region : Text })
  , http_protocols = None (List Text)
  , id = None Text
  , name = None Text
  , tls_protocols = None (List Text)
  , tls_service = None Text
  , updated_at = None Text
  }
}
