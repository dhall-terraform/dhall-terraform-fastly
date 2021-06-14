{ Type =
    { created_at : Optional Text
    , domains : Optional (List Text)
    , id : Optional Text
    , issued_to : Optional Text
    , issuer : Optional Text
    , name : Optional Text
    , replace : Optional Bool
    , serial_number : Optional Text
    , signature_algorithm : Optional Text
    , updated_at : Optional Text
    }
, default =
  { created_at = None Text
  , domains = None (List Text)
  , id = None Text
  , issued_to = None Text
  , issuer = None Text
  , name = None Text
  , replace = None Bool
  , serial_number = None Text
  , signature_algorithm = None Text
  , updated_at = None Text
  }
}
