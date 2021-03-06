{ Type =
    { cidr_blocks : Optional (List Text)
    , id : Optional Text
    , ipv6_cidr_blocks : Optional (List Text)
    }
, default =
  { cidr_blocks = None (List Text)
  , id = None Text
  , ipv6_cidr_blocks = None (List Text)
  }
}
