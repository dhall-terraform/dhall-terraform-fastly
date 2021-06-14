{ Type =
    { domain : Text
    , id : Optional Text
    , tls_activation_ids : Optional (List Text)
    , tls_certificate_ids : Optional (List Text)
    , tls_subscription_ids : Optional (List Text)
    }
, default =
  { id = None Text
  , tls_activation_ids = None (List Text)
  , tls_certificate_ids = None (List Text)
  , tls_subscription_ids = None (List Text)
  }
}
