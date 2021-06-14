{ Type =
    { certificate_authority : Text
    , common_name : Optional Text
    , configuration_id : Optional Text
    , created_at : Optional Text
    , domains : List Text
    , force_destroy : Optional Bool
    , force_update : Optional Bool
    , id : Optional Text
    , managed_dns_challenge : Optional (List { mapKey : Text, mapValue : Text })
    , managed_http_challenges :
        Optional
          ( List
              { record_name : Text
              , record_type : Text
              , record_values : List Text
              }
          )
    , state : Optional Text
    , updated_at : Optional Text
    }
, default =
  { common_name = None Text
  , configuration_id = None Text
  , created_at = None Text
  , force_destroy = None Bool
  , force_update = None Bool
  , id = None Text
  , managed_dns_challenge = None (List { mapKey : Text, mapValue : Text })
  , managed_http_challenges =
      None
        ( List
            { record_name : Text
            , record_type : Text
            , record_values : List Text
            }
        )
  , state = None Text
  , updated_at = None Text
  }
}
