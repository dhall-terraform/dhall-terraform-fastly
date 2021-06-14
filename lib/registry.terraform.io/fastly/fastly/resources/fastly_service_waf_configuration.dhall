{ Type =
    { allowed_http_versions : Optional Text
    , allowed_methods : Optional Text
    , allowed_request_content_type : Optional Text
    , allowed_request_content_type_charset : Optional Text
    , arg_length : Optional Natural
    , arg_name_length : Optional Natural
    , combined_file_sizes : Optional Natural
    , critical_anomaly_score : Optional Natural
    , crs_validate_utf8_encoding : Optional Bool
    , error_anomaly_score : Optional Natural
    , high_risk_country_codes : Optional Text
    , http_violation_score_threshold : Optional Natural
    , id : Optional Text
    , inbound_anomaly_score_threshold : Optional Natural
    , lfi_score_threshold : Optional Natural
    , max_file_size : Optional Natural
    , max_num_args : Optional Natural
    , notice_anomaly_score : Optional Natural
    , paranoia_level : Optional Natural
    , php_injection_score_threshold : Optional Natural
    , rce_score_threshold : Optional Natural
    , restricted_extensions : Optional Text
    , restricted_headers : Optional Text
    , rfi_score_threshold : Optional Natural
    , session_fixation_score_threshold : Optional Natural
    , sql_injection_score_threshold : Optional Natural
    , total_arg_length : Optional Natural
    , waf_id : Text
    , warning_anomaly_score : Optional Natural
    , xss_score_threshold : Optional Natural
    , rule :
        Optional
          ( List
              { modsec_rule_id : Natural
              , revision : Optional Natural
              , status : Text
              }
          )
    , rule_exclusion :
        Optional
          ( List
              { condition : Text
              , exclusion_type : Text
              , modsec_rule_ids : Optional (List Natural)
              , name : Text
              , number : Optional Natural
              }
          )
    }
, default =
  { allowed_http_versions = None Text
  , allowed_methods = None Text
  , allowed_request_content_type = None Text
  , allowed_request_content_type_charset = None Text
  , arg_length = None Natural
  , arg_name_length = None Natural
  , combined_file_sizes = None Natural
  , critical_anomaly_score = None Natural
  , crs_validate_utf8_encoding = None Bool
  , error_anomaly_score = None Natural
  , high_risk_country_codes = None Text
  , http_violation_score_threshold = None Natural
  , id = None Text
  , inbound_anomaly_score_threshold = None Natural
  , lfi_score_threshold = None Natural
  , max_file_size = None Natural
  , max_num_args = None Natural
  , notice_anomaly_score = None Natural
  , paranoia_level = None Natural
  , php_injection_score_threshold = None Natural
  , rce_score_threshold = None Natural
  , restricted_extensions = None Text
  , restricted_headers = None Text
  , rfi_score_threshold = None Natural
  , session_fixation_score_threshold = None Natural
  , sql_injection_score_threshold = None Natural
  , total_arg_length = None Natural
  , warning_anomaly_score = None Natural
  , xss_score_threshold = None Natural
  , rule =
      None
        ( List
            { modsec_rule_id : Natural
            , revision : Optional Natural
            , status : Text
            }
        )
  , rule_exclusion =
      None
        ( List
            { condition : Text
            , exclusion_type : Text
            , modsec_rule_ids : Optional (List Natural)
            , name : Text
            , number : Optional Natural
            }
        )
  }
}
