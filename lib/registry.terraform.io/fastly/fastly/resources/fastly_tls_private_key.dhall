{ Type =
    { created_at : Optional Text
    , id : Optional Text
    , key_length : Optional Natural
    , key_pem : Text
    , key_type : Optional Text
    , name : Text
    , public_key_sha1 : Optional Text
    , replace : Optional Bool
    }
, default =
  { created_at = None Text
  , id = None Text
  , key_length = None Natural
  , key_type = None Text
  , public_key_sha1 = None Text
  , replace = None Bool
  }
}
