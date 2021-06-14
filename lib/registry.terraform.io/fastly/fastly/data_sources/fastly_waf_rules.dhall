{ Type =
    { exclude_modsec_rule_ids : Optional (List Natural)
    , id : Optional Text
    , publishers : Optional (List Text)
    , rules :
        Optional
          ( List
              { latest_revision_number : Natural
              , modsec_rule_id : Natural
              , type : Text
              }
          )
    , tags : Optional (List Text)
    }
, default =
  { exclude_modsec_rule_ids = None (List Natural)
  , id = None Text
  , publishers = None (List Text)
  , rules =
      None
        ( List
            { latest_revision_number : Natural
            , modsec_rule_id : Natural
            , type : Text
            }
        )
  , tags = None (List Text)
  }
}
