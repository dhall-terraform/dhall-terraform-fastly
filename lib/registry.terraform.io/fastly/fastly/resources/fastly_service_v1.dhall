{ Type =
    { activate : Optional Bool
    , active_version : Optional Natural
    , cloned_version : Optional Natural
    , comment : Optional Text
    , default_host : Optional Text
    , default_ttl : Optional Natural
    , force_destroy : Optional Bool
    , id : Optional Text
    , name : Text
    , version_comment : Optional Text
    , acl :
        Optional
          ( List
              { acl_id : Optional Text
              , force_destroy : Optional Bool
              , name : Text
              }
          )
    , backend :
        List
          { address : Text
          , auto_loadbalance : Optional Bool
          , between_bytes_timeout : Optional Natural
          , connect_timeout : Optional Natural
          , error_threshold : Optional Natural
          , first_byte_timeout : Optional Natural
          , healthcheck : Optional Text
          , max_conn : Optional Natural
          , max_tls_version : Optional Text
          , min_tls_version : Optional Text
          , name : Text
          , override_host : Optional Text
          , port : Optional Natural
          , request_condition : Optional Text
          , shield : Optional Text
          , ssl_ca_cert : Optional Text
          , ssl_cert_hostname : Optional Text
          , ssl_check_cert : Optional Bool
          , ssl_ciphers : Optional Text
          , ssl_client_cert : Optional Text
          , ssl_client_key : Optional Text
          , ssl_hostname : Optional Text
          , ssl_sni_hostname : Optional Text
          , use_ssl : Optional Bool
          , weight : Optional Natural
          }
    , bigquerylogging :
        Optional
          ( List
              { dataset : Text
              , email : Optional Text
              , format : Optional Text
              , name : Text
              , placement : Optional Text
              , project_id : Text
              , response_condition : Optional Text
              , secret_key : Optional Text
              , table : Text
              , template : Optional Text
              }
          )
    , blobstoragelogging :
        Optional
          ( List
              { account_name : Text
              , compression_codec : Optional Text
              , container : Text
              , file_max_bytes : Optional Natural
              , format : Optional Text
              , format_version : Optional Natural
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , path : Optional Text
              , period : Optional Natural
              , placement : Optional Text
              , public_key : Optional Text
              , response_condition : Optional Text
              , sas_token : Optional Text
              , timestamp_format : Optional Text
              }
          )
    , cache_setting :
        Optional
          ( List
              { action : Optional Text
              , cache_condition : Optional Text
              , name : Text
              , stale_ttl : Optional Natural
              , ttl : Optional Natural
              }
          )
    , condition :
        Optional
          ( List
              { name : Text
              , priority : Optional Natural
              , statement : Text
              , type : Text
              }
          )
    , dictionary :
        Optional
          ( List
              { dictionary_id : Optional Text
              , force_destroy : Optional Bool
              , name : Text
              , write_only : Optional Bool
              }
          )
    , director :
        Optional
          ( List
              { backends : List Text
              , capacity : Optional Natural
              , comment : Optional Text
              , name : Text
              , quorum : Optional Natural
              , retries : Optional Natural
              , shield : Optional Text
              , type : Optional Natural
              }
          )
    , domain : List { comment : Optional Text, name : Text }
    , dynamicsnippet :
        Optional
          ( List
              { name : Text
              , priority : Optional Natural
              , snippet_id : Optional Text
              , type : Text
              }
          )
    , gcslogging :
        Optional
          ( List
              { bucket_name : Text
              , compression_codec : Optional Text
              , email : Optional Text
              , format : Optional Text
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , path : Optional Text
              , period : Optional Natural
              , placement : Optional Text
              , response_condition : Optional Text
              , secret_key : Optional Text
              , timestamp_format : Optional Text
              }
          )
    , gzip :
        Optional
          ( List
              { cache_condition : Optional Text
              , content_types : Optional (List Text)
              , extensions : Optional (List Text)
              , name : Text
              }
          )
    , header :
        Optional
          ( List
              { action : Text
              , cache_condition : Optional Text
              , destination : Text
              , ignore_if_set : Optional Bool
              , name : Text
              , priority : Optional Natural
              , regex : Optional Text
              , request_condition : Optional Text
              , response_condition : Optional Text
              , source : Optional Text
              , substitution : Optional Text
              , type : Text
              }
          )
    , healthcheck :
        Optional
          ( List
              { check_interval : Optional Natural
              , expected_response : Optional Natural
              , host : Text
              , http_version : Optional Text
              , initial : Optional Natural
              , method : Optional Text
              , name : Text
              , path : Text
              , threshold : Optional Natural
              , timeout : Optional Natural
              , window : Optional Natural
              }
          )
    , httpslogging :
        Optional
          ( List
              { content_type : Optional Text
              , format : Optional Text
              , format_version : Optional Natural
              , header_name : Optional Text
              , header_value : Optional Text
              , json_format : Optional Text
              , message_type : Optional Text
              , method : Optional Text
              , name : Text
              , placement : Optional Text
              , request_max_bytes : Optional Natural
              , request_max_entries : Optional Natural
              , response_condition : Optional Text
              , tls_ca_cert : Optional Text
              , tls_client_cert : Optional Text
              , tls_client_key : Optional Text
              , tls_hostname : Optional Text
              , url : Text
              }
          )
    , logentries :
        Optional
          ( List
              { format : Optional Text
              , format_version : Optional Natural
              , name : Text
              , placement : Optional Text
              , port : Optional Natural
              , response_condition : Optional Text
              , token : Text
              , use_tls : Optional Bool
              }
          )
    , logging_cloudfiles :
        Optional
          ( List
              { access_key : Text
              , bucket_name : Text
              , compression_codec : Optional Text
              , format : Optional Text
              , format_version : Optional Natural
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , path : Optional Text
              , period : Optional Natural
              , placement : Optional Text
              , public_key : Optional Text
              , region : Optional Text
              , response_condition : Optional Text
              , timestamp_format : Optional Text
              , user : Text
              }
          )
    , logging_datadog :
        Optional
          ( List
              { format : Optional Text
              , format_version : Optional Natural
              , name : Text
              , placement : Optional Text
              , region : Optional Text
              , response_condition : Optional Text
              , token : Text
              }
          )
    , logging_digitalocean :
        Optional
          ( List
              { access_key : Text
              , bucket_name : Text
              , compression_codec : Optional Text
              , domain : Optional Text
              , format : Optional Text
              , format_version : Optional Natural
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , path : Optional Text
              , period : Optional Natural
              , placement : Optional Text
              , public_key : Optional Text
              , response_condition : Optional Text
              , secret_key : Text
              , timestamp_format : Optional Text
              }
          )
    , logging_elasticsearch :
        Optional
          ( List
              { format : Optional Text
              , format_version : Optional Natural
              , index : Text
              , name : Text
              , password : Optional Text
              , pipeline : Optional Text
              , placement : Optional Text
              , request_max_bytes : Optional Natural
              , request_max_entries : Optional Natural
              , response_condition : Optional Text
              , tls_ca_cert : Optional Text
              , tls_client_cert : Optional Text
              , tls_client_key : Optional Text
              , tls_hostname : Optional Text
              , url : Text
              , user : Optional Text
              }
          )
    , logging_ftp :
        Optional
          ( List
              { address : Text
              , compression_codec : Optional Text
              , format : Optional Text
              , format_version : Optional Natural
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , password : Text
              , path : Text
              , period : Optional Natural
              , placement : Optional Text
              , port : Optional Natural
              , public_key : Optional Text
              , response_condition : Optional Text
              , timestamp_format : Optional Text
              , user : Text
              }
          )
    , logging_googlepubsub :
        Optional
          ( List
              { format : Optional Text
              , format_version : Optional Natural
              , name : Text
              , placement : Optional Text
              , project_id : Text
              , response_condition : Optional Text
              , secret_key : Optional Text
              , topic : Text
              , user : Optional Text
              }
          )
    , logging_heroku :
        Optional
          ( List
              { format : Optional Text
              , format_version : Optional Natural
              , name : Text
              , placement : Optional Text
              , response_condition : Optional Text
              , token : Text
              , url : Text
              }
          )
    , logging_honeycomb :
        Optional
          ( List
              { dataset : Text
              , format : Optional Text
              , format_version : Optional Natural
              , name : Text
              , placement : Optional Text
              , response_condition : Optional Text
              , token : Text
              }
          )
    , logging_kafka :
        Optional
          ( List
              { auth_method : Optional Text
              , brokers : Text
              , compression_codec : Optional Text
              , format : Optional Text
              , format_version : Optional Natural
              , name : Text
              , parse_log_keyvals : Optional Bool
              , password : Optional Text
              , placement : Optional Text
              , request_max_bytes : Optional Natural
              , required_acks : Optional Text
              , response_condition : Optional Text
              , tls_ca_cert : Optional Text
              , tls_client_cert : Optional Text
              , tls_client_key : Optional Text
              , tls_hostname : Optional Text
              , topic : Text
              , use_tls : Optional Bool
              , user : Optional Text
              }
          )
    , logging_kinesis :
        Optional
          ( List
              { access_key : Optional Text
              , format : Optional Text
              , format_version : Optional Natural
              , iam_role : Optional Text
              , name : Text
              , placement : Optional Text
              , region : Optional Text
              , response_condition : Optional Text
              , secret_key : Optional Text
              , topic : Text
              }
          )
    , logging_loggly :
        Optional
          ( List
              { format : Optional Text
              , format_version : Optional Natural
              , name : Text
              , placement : Optional Text
              , response_condition : Optional Text
              , token : Text
              }
          )
    , logging_logshuttle :
        Optional
          ( List
              { format : Optional Text
              , format_version : Optional Natural
              , name : Text
              , placement : Optional Text
              , response_condition : Optional Text
              , token : Text
              , url : Text
              }
          )
    , logging_newrelic :
        Optional
          ( List
              { format : Optional Text
              , format_version : Optional Natural
              , name : Text
              , placement : Optional Text
              , response_condition : Optional Text
              , token : Text
              }
          )
    , logging_openstack :
        Optional
          ( List
              { access_key : Text
              , bucket_name : Text
              , compression_codec : Optional Text
              , format : Optional Text
              , format_version : Optional Natural
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , path : Optional Text
              , period : Optional Natural
              , placement : Optional Text
              , public_key : Optional Text
              , response_condition : Optional Text
              , timestamp_format : Optional Text
              , url : Text
              , user : Text
              }
          )
    , logging_scalyr :
        Optional
          ( List
              { format : Optional Text
              , format_version : Optional Natural
              , name : Text
              , placement : Optional Text
              , region : Optional Text
              , response_condition : Optional Text
              , token : Text
              }
          )
    , logging_sftp :
        Optional
          ( List
              { address : Text
              , compression_codec : Optional Text
              , format : Optional Text
              , format_version : Optional Natural
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , password : Optional Text
              , path : Text
              , period : Optional Natural
              , placement : Optional Text
              , port : Optional Natural
              , public_key : Optional Text
              , response_condition : Optional Text
              , secret_key : Optional Text
              , ssh_known_hosts : Text
              , timestamp_format : Optional Text
              , user : Text
              }
          )
    , papertrail :
        Optional
          ( List
              { address : Text
              , format : Optional Text
              , format_version : Optional Natural
              , name : Text
              , placement : Optional Text
              , port : Natural
              , response_condition : Optional Text
              }
          )
    , request_setting :
        Optional
          ( List
              { action : Optional Text
              , bypass_busy_wait : Optional Bool
              , default_host : Optional Text
              , force_miss : Optional Bool
              , force_ssl : Optional Bool
              , geo_headers : Optional Bool
              , hash_keys : Optional Text
              , max_stale_age : Optional Natural
              , name : Text
              , request_condition : Optional Text
              , timer_support : Optional Bool
              , xff : Optional Text
              }
          )
    , response_object :
        Optional
          ( List
              { cache_condition : Optional Text
              , content : Optional Text
              , content_type : Optional Text
              , name : Text
              , request_condition : Optional Text
              , response : Optional Text
              , status : Optional Natural
              }
          )
    , s3logging :
        Optional
          ( List
              { acl : Optional Text
              , bucket_name : Text
              , compression_codec : Optional Text
              , domain : Optional Text
              , format : Optional Text
              , format_version : Optional Natural
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , path : Optional Text
              , period : Optional Natural
              , placement : Optional Text
              , public_key : Optional Text
              , redundancy : Optional Text
              , response_condition : Optional Text
              , s3_access_key : Optional Text
              , s3_iam_role : Optional Text
              , s3_secret_key : Optional Text
              , server_side_encryption : Optional Text
              , server_side_encryption_kms_key_id : Optional Text
              , timestamp_format : Optional Text
              }
          )
    , snippet :
        Optional
          ( List
              { content : Text
              , name : Text
              , priority : Optional Natural
              , type : Text
              }
          )
    , splunk :
        Optional
          ( List
              { format : Optional Text
              , format_version : Optional Natural
              , name : Text
              , placement : Optional Text
              , response_condition : Optional Text
              , tls_ca_cert : Optional Text
              , tls_client_cert : Optional Text
              , tls_client_key : Optional Text
              , tls_hostname : Optional Text
              , token : Optional Text
              , url : Text
              }
          )
    , sumologic :
        Optional
          ( List
              { format : Optional Text
              , format_version : Optional Natural
              , message_type : Optional Text
              , name : Text
              , placement : Optional Text
              , response_condition : Optional Text
              , url : Text
              }
          )
    , syslog :
        Optional
          ( List
              { address : Text
              , format : Optional Text
              , format_version : Optional Natural
              , message_type : Optional Text
              , name : Text
              , placement : Optional Text
              , port : Optional Natural
              , response_condition : Optional Text
              , tls_ca_cert : Optional Text
              , tls_client_cert : Optional Text
              , tls_client_key : Optional Text
              , tls_hostname : Optional Text
              , token : Optional Text
              , use_tls : Optional Bool
              }
          )
    , vcl :
        Optional (List { content : Text, main : Optional Bool, name : Text })
    , waf :
        Optional
          ( List
              { disabled : Optional Bool
              , prefetch_condition : Optional Text
              , response_object : Text
              , waf_id : Optional Text
              }
          )
    }
, default =
  { activate = None Bool
  , active_version = None Natural
  , cloned_version = None Natural
  , comment = None Text
  , default_host = None Text
  , default_ttl = None Natural
  , force_destroy = None Bool
  , id = None Text
  , version_comment = None Text
  , acl =
      None
        ( List
            { acl_id : Optional Text
            , force_destroy : Optional Bool
            , name : Text
            }
        )
  , bigquerylogging =
      None
        ( List
            { dataset : Text
            , email : Optional Text
            , format : Optional Text
            , name : Text
            , placement : Optional Text
            , project_id : Text
            , response_condition : Optional Text
            , secret_key : Optional Text
            , table : Text
            , template : Optional Text
            }
        )
  , blobstoragelogging =
      None
        ( List
            { account_name : Text
            , compression_codec : Optional Text
            , container : Text
            , file_max_bytes : Optional Natural
            , format : Optional Text
            , format_version : Optional Natural
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , path : Optional Text
            , period : Optional Natural
            , placement : Optional Text
            , public_key : Optional Text
            , response_condition : Optional Text
            , sas_token : Optional Text
            , timestamp_format : Optional Text
            }
        )
  , cache_setting =
      None
        ( List
            { action : Optional Text
            , cache_condition : Optional Text
            , name : Text
            , stale_ttl : Optional Natural
            , ttl : Optional Natural
            }
        )
  , condition =
      None
        ( List
            { name : Text
            , priority : Optional Natural
            , statement : Text
            , type : Text
            }
        )
  , dictionary =
      None
        ( List
            { dictionary_id : Optional Text
            , force_destroy : Optional Bool
            , name : Text
            , write_only : Optional Bool
            }
        )
  , director =
      None
        ( List
            { backends : List Text
            , capacity : Optional Natural
            , comment : Optional Text
            , name : Text
            , quorum : Optional Natural
            , retries : Optional Natural
            , shield : Optional Text
            , type : Optional Natural
            }
        )
  , dynamicsnippet =
      None
        ( List
            { name : Text
            , priority : Optional Natural
            , snippet_id : Optional Text
            , type : Text
            }
        )
  , gcslogging =
      None
        ( List
            { bucket_name : Text
            , compression_codec : Optional Text
            , email : Optional Text
            , format : Optional Text
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , path : Optional Text
            , period : Optional Natural
            , placement : Optional Text
            , response_condition : Optional Text
            , secret_key : Optional Text
            , timestamp_format : Optional Text
            }
        )
  , gzip =
      None
        ( List
            { cache_condition : Optional Text
            , content_types : Optional (List Text)
            , extensions : Optional (List Text)
            , name : Text
            }
        )
  , header =
      None
        ( List
            { action : Text
            , cache_condition : Optional Text
            , destination : Text
            , ignore_if_set : Optional Bool
            , name : Text
            , priority : Optional Natural
            , regex : Optional Text
            , request_condition : Optional Text
            , response_condition : Optional Text
            , source : Optional Text
            , substitution : Optional Text
            , type : Text
            }
        )
  , healthcheck =
      None
        ( List
            { check_interval : Optional Natural
            , expected_response : Optional Natural
            , host : Text
            , http_version : Optional Text
            , initial : Optional Natural
            , method : Optional Text
            , name : Text
            , path : Text
            , threshold : Optional Natural
            , timeout : Optional Natural
            , window : Optional Natural
            }
        )
  , httpslogging =
      None
        ( List
            { content_type : Optional Text
            , format : Optional Text
            , format_version : Optional Natural
            , header_name : Optional Text
            , header_value : Optional Text
            , json_format : Optional Text
            , message_type : Optional Text
            , method : Optional Text
            , name : Text
            , placement : Optional Text
            , request_max_bytes : Optional Natural
            , request_max_entries : Optional Natural
            , response_condition : Optional Text
            , tls_ca_cert : Optional Text
            , tls_client_cert : Optional Text
            , tls_client_key : Optional Text
            , tls_hostname : Optional Text
            , url : Text
            }
        )
  , logentries =
      None
        ( List
            { format : Optional Text
            , format_version : Optional Natural
            , name : Text
            , placement : Optional Text
            , port : Optional Natural
            , response_condition : Optional Text
            , token : Text
            , use_tls : Optional Bool
            }
        )
  , logging_cloudfiles =
      None
        ( List
            { access_key : Text
            , bucket_name : Text
            , compression_codec : Optional Text
            , format : Optional Text
            , format_version : Optional Natural
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , path : Optional Text
            , period : Optional Natural
            , placement : Optional Text
            , public_key : Optional Text
            , region : Optional Text
            , response_condition : Optional Text
            , timestamp_format : Optional Text
            , user : Text
            }
        )
  , logging_datadog =
      None
        ( List
            { format : Optional Text
            , format_version : Optional Natural
            , name : Text
            , placement : Optional Text
            , region : Optional Text
            , response_condition : Optional Text
            , token : Text
            }
        )
  , logging_digitalocean =
      None
        ( List
            { access_key : Text
            , bucket_name : Text
            , compression_codec : Optional Text
            , domain : Optional Text
            , format : Optional Text
            , format_version : Optional Natural
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , path : Optional Text
            , period : Optional Natural
            , placement : Optional Text
            , public_key : Optional Text
            , response_condition : Optional Text
            , secret_key : Text
            , timestamp_format : Optional Text
            }
        )
  , logging_elasticsearch =
      None
        ( List
            { format : Optional Text
            , format_version : Optional Natural
            , index : Text
            , name : Text
            , password : Optional Text
            , pipeline : Optional Text
            , placement : Optional Text
            , request_max_bytes : Optional Natural
            , request_max_entries : Optional Natural
            , response_condition : Optional Text
            , tls_ca_cert : Optional Text
            , tls_client_cert : Optional Text
            , tls_client_key : Optional Text
            , tls_hostname : Optional Text
            , url : Text
            , user : Optional Text
            }
        )
  , logging_ftp =
      None
        ( List
            { address : Text
            , compression_codec : Optional Text
            , format : Optional Text
            , format_version : Optional Natural
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , password : Text
            , path : Text
            , period : Optional Natural
            , placement : Optional Text
            , port : Optional Natural
            , public_key : Optional Text
            , response_condition : Optional Text
            , timestamp_format : Optional Text
            , user : Text
            }
        )
  , logging_googlepubsub =
      None
        ( List
            { format : Optional Text
            , format_version : Optional Natural
            , name : Text
            , placement : Optional Text
            , project_id : Text
            , response_condition : Optional Text
            , secret_key : Optional Text
            , topic : Text
            , user : Optional Text
            }
        )
  , logging_heroku =
      None
        ( List
            { format : Optional Text
            , format_version : Optional Natural
            , name : Text
            , placement : Optional Text
            , response_condition : Optional Text
            , token : Text
            , url : Text
            }
        )
  , logging_honeycomb =
      None
        ( List
            { dataset : Text
            , format : Optional Text
            , format_version : Optional Natural
            , name : Text
            , placement : Optional Text
            , response_condition : Optional Text
            , token : Text
            }
        )
  , logging_kafka =
      None
        ( List
            { auth_method : Optional Text
            , brokers : Text
            , compression_codec : Optional Text
            , format : Optional Text
            , format_version : Optional Natural
            , name : Text
            , parse_log_keyvals : Optional Bool
            , password : Optional Text
            , placement : Optional Text
            , request_max_bytes : Optional Natural
            , required_acks : Optional Text
            , response_condition : Optional Text
            , tls_ca_cert : Optional Text
            , tls_client_cert : Optional Text
            , tls_client_key : Optional Text
            , tls_hostname : Optional Text
            , topic : Text
            , use_tls : Optional Bool
            , user : Optional Text
            }
        )
  , logging_kinesis =
      None
        ( List
            { access_key : Optional Text
            , format : Optional Text
            , format_version : Optional Natural
            , iam_role : Optional Text
            , name : Text
            , placement : Optional Text
            , region : Optional Text
            , response_condition : Optional Text
            , secret_key : Optional Text
            , topic : Text
            }
        )
  , logging_loggly =
      None
        ( List
            { format : Optional Text
            , format_version : Optional Natural
            , name : Text
            , placement : Optional Text
            , response_condition : Optional Text
            , token : Text
            }
        )
  , logging_logshuttle =
      None
        ( List
            { format : Optional Text
            , format_version : Optional Natural
            , name : Text
            , placement : Optional Text
            , response_condition : Optional Text
            , token : Text
            , url : Text
            }
        )
  , logging_newrelic =
      None
        ( List
            { format : Optional Text
            , format_version : Optional Natural
            , name : Text
            , placement : Optional Text
            , response_condition : Optional Text
            , token : Text
            }
        )
  , logging_openstack =
      None
        ( List
            { access_key : Text
            , bucket_name : Text
            , compression_codec : Optional Text
            , format : Optional Text
            , format_version : Optional Natural
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , path : Optional Text
            , period : Optional Natural
            , placement : Optional Text
            , public_key : Optional Text
            , response_condition : Optional Text
            , timestamp_format : Optional Text
            , url : Text
            , user : Text
            }
        )
  , logging_scalyr =
      None
        ( List
            { format : Optional Text
            , format_version : Optional Natural
            , name : Text
            , placement : Optional Text
            , region : Optional Text
            , response_condition : Optional Text
            , token : Text
            }
        )
  , logging_sftp =
      None
        ( List
            { address : Text
            , compression_codec : Optional Text
            , format : Optional Text
            , format_version : Optional Natural
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , password : Optional Text
            , path : Text
            , period : Optional Natural
            , placement : Optional Text
            , port : Optional Natural
            , public_key : Optional Text
            , response_condition : Optional Text
            , secret_key : Optional Text
            , ssh_known_hosts : Text
            , timestamp_format : Optional Text
            , user : Text
            }
        )
  , papertrail =
      None
        ( List
            { address : Text
            , format : Optional Text
            , format_version : Optional Natural
            , name : Text
            , placement : Optional Text
            , port : Natural
            , response_condition : Optional Text
            }
        )
  , request_setting =
      None
        ( List
            { action : Optional Text
            , bypass_busy_wait : Optional Bool
            , default_host : Optional Text
            , force_miss : Optional Bool
            , force_ssl : Optional Bool
            , geo_headers : Optional Bool
            , hash_keys : Optional Text
            , max_stale_age : Optional Natural
            , name : Text
            , request_condition : Optional Text
            , timer_support : Optional Bool
            , xff : Optional Text
            }
        )
  , response_object =
      None
        ( List
            { cache_condition : Optional Text
            , content : Optional Text
            , content_type : Optional Text
            , name : Text
            , request_condition : Optional Text
            , response : Optional Text
            , status : Optional Natural
            }
        )
  , s3logging =
      None
        ( List
            { acl : Optional Text
            , bucket_name : Text
            , compression_codec : Optional Text
            , domain : Optional Text
            , format : Optional Text
            , format_version : Optional Natural
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , path : Optional Text
            , period : Optional Natural
            , placement : Optional Text
            , public_key : Optional Text
            , redundancy : Optional Text
            , response_condition : Optional Text
            , s3_access_key : Optional Text
            , s3_iam_role : Optional Text
            , s3_secret_key : Optional Text
            , server_side_encryption : Optional Text
            , server_side_encryption_kms_key_id : Optional Text
            , timestamp_format : Optional Text
            }
        )
  , snippet =
      None
        ( List
            { content : Text
            , name : Text
            , priority : Optional Natural
            , type : Text
            }
        )
  , splunk =
      None
        ( List
            { format : Optional Text
            , format_version : Optional Natural
            , name : Text
            , placement : Optional Text
            , response_condition : Optional Text
            , tls_ca_cert : Optional Text
            , tls_client_cert : Optional Text
            , tls_client_key : Optional Text
            , tls_hostname : Optional Text
            , token : Optional Text
            , url : Text
            }
        )
  , sumologic =
      None
        ( List
            { format : Optional Text
            , format_version : Optional Natural
            , message_type : Optional Text
            , name : Text
            , placement : Optional Text
            , response_condition : Optional Text
            , url : Text
            }
        )
  , syslog =
      None
        ( List
            { address : Text
            , format : Optional Text
            , format_version : Optional Natural
            , message_type : Optional Text
            , name : Text
            , placement : Optional Text
            , port : Optional Natural
            , response_condition : Optional Text
            , tls_ca_cert : Optional Text
            , tls_client_cert : Optional Text
            , tls_client_key : Optional Text
            , tls_hostname : Optional Text
            , token : Optional Text
            , use_tls : Optional Bool
            }
        )
  , vcl = None (List { content : Text, main : Optional Bool, name : Text })
  , waf =
      None
        ( List
            { disabled : Optional Bool
            , prefetch_condition : Optional Text
            , response_object : Text
            , waf_id : Optional Text
            }
        )
  }
}
