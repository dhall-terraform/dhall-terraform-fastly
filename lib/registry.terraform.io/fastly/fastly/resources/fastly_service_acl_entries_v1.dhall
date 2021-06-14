{ Type =
    { acl_id : Text
    , id : Optional Text
    , service_id : Text
    , entry :
        Optional
          ( List
              { comment : Optional Text
              , id : Optional Text
              , ip : Text
              , negated : Optional Bool
              , subnet : Optional Text
              }
          )
    }
, default =
  { id = None Text
  , entry =
      None
        ( List
            { comment : Optional Text
            , id : Optional Text
            , ip : Text
            , negated : Optional Bool
            , subnet : Optional Text
            }
        )
  }
}
