{ Type =
    { allow_untrusted_root : Optional Bool
    , certificate_body : Text
    , configuration_id : Text
    , created_at : Optional Text
    , domains : Optional (List Text)
    , id : Optional Text
    , intermediates_blob : Text
    , not_after : Optional Text
    , not_before : Optional Text
    , replace : Optional Bool
    , updated_at : Optional Text
    }
, default =
  { allow_untrusted_root = None Bool
  , created_at = None Text
  , domains = None (List Text)
  , id = None Text
  , not_after = None Text
  , not_before = None Text
  , replace = None Bool
  , updated_at = None Text
  }
}
