{ Type =
    { dictionary_id : Text
    , id : Optional Text
    , items : Optional (List { mapKey : Text, mapValue : Text })
    , service_id : Text
    }
, default =
  { id = None Text, items = None (List { mapKey : Text, mapValue : Text }) }
}
