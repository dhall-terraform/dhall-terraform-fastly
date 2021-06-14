{ Type =
    { certificate_authority : Optional Text
    , common_name : Optional Text
    , configuration_id : Optional Text
    , created_at : Optional Text
    , domains : Optional (List Text)
    , id : Optional Text
    , state : Optional Text
    , updated_at : Optional Text
    }
, default =
  { certificate_authority = None Text
  , common_name = None Text
  , configuration_id = None Text
  , created_at = None Text
  , domains = None (List Text)
  , id = None Text
  , state = None Text
  , updated_at = None Text
  }
}
