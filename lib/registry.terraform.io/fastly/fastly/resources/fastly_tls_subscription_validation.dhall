{ Type =
    { id : Optional Text
    , subscription_id : Text
    , timeouts : Optional { create : Optional Text }
    }
, default = { id = None Text, timeouts = None { create : Optional Text } }
}
