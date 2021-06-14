{ Type =
    { activate : Optional Bool
    , active_version : Optional Natural
    , cloned_version : Optional Natural
    , comment : Optional Text
    , force_destroy : Optional Bool
    , id : Optional Text
    , name : Text
    , version_comment : Optional Text
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
              , name : Text
              , project_id : Text
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
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , path : Optional Text
              , period : Optional Natural
              , public_key : Optional Text
              , sas_token : Optional Text
              , timestamp_format : Optional Text
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
    , gcslogging :
        Optional
          ( List
              { bucket_name : Text
              , compression_codec : Optional Text
              , email : Optional Text
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , path : Optional Text
              , period : Optional Natural
              , secret_key : Optional Text
              , timestamp_format : Optional Text
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
              , header_name : Optional Text
              , header_value : Optional Text
              , json_format : Optional Text
              , message_type : Optional Text
              , method : Optional Text
              , name : Text
              , request_max_bytes : Optional Natural
              , request_max_entries : Optional Natural
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
              { name : Text
              , port : Optional Natural
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
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , path : Optional Text
              , period : Optional Natural
              , public_key : Optional Text
              , region : Optional Text
              , timestamp_format : Optional Text
              , user : Text
              }
          )
    , logging_datadog :
        Optional (List { name : Text, region : Optional Text, token : Text })
    , logging_digitalocean :
        Optional
          ( List
              { access_key : Text
              , bucket_name : Text
              , compression_codec : Optional Text
              , domain : Optional Text
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , path : Optional Text
              , period : Optional Natural
              , public_key : Optional Text
              , secret_key : Text
              , timestamp_format : Optional Text
              }
          )
    , logging_elasticsearch :
        Optional
          ( List
              { index : Text
              , name : Text
              , password : Optional Text
              , pipeline : Optional Text
              , request_max_bytes : Optional Natural
              , request_max_entries : Optional Natural
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
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , password : Text
              , path : Text
              , period : Optional Natural
              , port : Optional Natural
              , public_key : Optional Text
              , timestamp_format : Optional Text
              , user : Text
              }
          )
    , logging_googlepubsub :
        Optional
          ( List
              { name : Text
              , project_id : Text
              , secret_key : Optional Text
              , topic : Text
              , user : Optional Text
              }
          )
    , logging_heroku : Optional (List { name : Text, token : Text, url : Text })
    , logging_honeycomb :
        Optional (List { dataset : Text, name : Text, token : Text })
    , logging_kafka :
        Optional
          ( List
              { auth_method : Optional Text
              , brokers : Text
              , compression_codec : Optional Text
              , name : Text
              , parse_log_keyvals : Optional Bool
              , password : Optional Text
              , request_max_bytes : Optional Natural
              , required_acks : Optional Text
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
              , iam_role : Optional Text
              , name : Text
              , region : Optional Text
              , secret_key : Optional Text
              , topic : Text
              }
          )
    , logging_loggly : Optional (List { name : Text, token : Text })
    , logging_logshuttle :
        Optional (List { name : Text, token : Text, url : Text })
    , logging_newrelic : Optional (List { name : Text, token : Text })
    , logging_openstack :
        Optional
          ( List
              { access_key : Text
              , bucket_name : Text
              , compression_codec : Optional Text
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , path : Optional Text
              , period : Optional Natural
              , public_key : Optional Text
              , timestamp_format : Optional Text
              , url : Text
              , user : Text
              }
          )
    , logging_scalyr :
        Optional (List { name : Text, region : Optional Text, token : Text })
    , logging_sftp :
        Optional
          ( List
              { address : Text
              , compression_codec : Optional Text
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , password : Optional Text
              , path : Text
              , period : Optional Natural
              , port : Optional Natural
              , public_key : Optional Text
              , secret_key : Optional Text
              , ssh_known_hosts : Text
              , timestamp_format : Optional Text
              , user : Text
              }
          )
    , package : List { filename : Text, source_code_hash : Optional Text }
    , papertrail :
        Optional (List { address : Text, name : Text, port : Natural })
    , s3logging :
        Optional
          ( List
              { acl : Optional Text
              , bucket_name : Text
              , compression_codec : Optional Text
              , domain : Optional Text
              , gzip_level : Optional Natural
              , message_type : Optional Text
              , name : Text
              , path : Optional Text
              , period : Optional Natural
              , public_key : Optional Text
              , redundancy : Optional Text
              , s3_access_key : Optional Text
              , s3_iam_role : Optional Text
              , s3_secret_key : Optional Text
              , server_side_encryption : Optional Text
              , server_side_encryption_kms_key_id : Optional Text
              , timestamp_format : Optional Text
              }
          )
    , splunk :
        Optional
          ( List
              { name : Text
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
          (List { message_type : Optional Text, name : Text, url : Text })
    , syslog :
        Optional
          ( List
              { address : Text
              , message_type : Optional Text
              , name : Text
              , port : Optional Natural
              , tls_ca_cert : Optional Text
              , tls_client_cert : Optional Text
              , tls_client_key : Optional Text
              , tls_hostname : Optional Text
              , token : Optional Text
              , use_tls : Optional Bool
              }
          )
    }
, default =
  { activate = None Bool
  , active_version = None Natural
  , cloned_version = None Natural
  , comment = None Text
  , force_destroy = None Bool
  , id = None Text
  , version_comment = None Text
  , bigquerylogging =
      None
        ( List
            { dataset : Text
            , email : Optional Text
            , name : Text
            , project_id : Text
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
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , path : Optional Text
            , period : Optional Natural
            , public_key : Optional Text
            , sas_token : Optional Text
            , timestamp_format : Optional Text
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
  , gcslogging =
      None
        ( List
            { bucket_name : Text
            , compression_codec : Optional Text
            , email : Optional Text
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , path : Optional Text
            , period : Optional Natural
            , secret_key : Optional Text
            , timestamp_format : Optional Text
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
            , header_name : Optional Text
            , header_value : Optional Text
            , json_format : Optional Text
            , message_type : Optional Text
            , method : Optional Text
            , name : Text
            , request_max_bytes : Optional Natural
            , request_max_entries : Optional Natural
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
            { name : Text
            , port : Optional Natural
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
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , path : Optional Text
            , period : Optional Natural
            , public_key : Optional Text
            , region : Optional Text
            , timestamp_format : Optional Text
            , user : Text
            }
        )
  , logging_datadog =
      None (List { name : Text, region : Optional Text, token : Text })
  , logging_digitalocean =
      None
        ( List
            { access_key : Text
            , bucket_name : Text
            , compression_codec : Optional Text
            , domain : Optional Text
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , path : Optional Text
            , period : Optional Natural
            , public_key : Optional Text
            , secret_key : Text
            , timestamp_format : Optional Text
            }
        )
  , logging_elasticsearch =
      None
        ( List
            { index : Text
            , name : Text
            , password : Optional Text
            , pipeline : Optional Text
            , request_max_bytes : Optional Natural
            , request_max_entries : Optional Natural
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
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , password : Text
            , path : Text
            , period : Optional Natural
            , port : Optional Natural
            , public_key : Optional Text
            , timestamp_format : Optional Text
            , user : Text
            }
        )
  , logging_googlepubsub =
      None
        ( List
            { name : Text
            , project_id : Text
            , secret_key : Optional Text
            , topic : Text
            , user : Optional Text
            }
        )
  , logging_heroku = None (List { name : Text, token : Text, url : Text })
  , logging_honeycomb =
      None (List { dataset : Text, name : Text, token : Text })
  , logging_kafka =
      None
        ( List
            { auth_method : Optional Text
            , brokers : Text
            , compression_codec : Optional Text
            , name : Text
            , parse_log_keyvals : Optional Bool
            , password : Optional Text
            , request_max_bytes : Optional Natural
            , required_acks : Optional Text
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
            , iam_role : Optional Text
            , name : Text
            , region : Optional Text
            , secret_key : Optional Text
            , topic : Text
            }
        )
  , logging_loggly = None (List { name : Text, token : Text })
  , logging_logshuttle = None (List { name : Text, token : Text, url : Text })
  , logging_newrelic = None (List { name : Text, token : Text })
  , logging_openstack =
      None
        ( List
            { access_key : Text
            , bucket_name : Text
            , compression_codec : Optional Text
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , path : Optional Text
            , period : Optional Natural
            , public_key : Optional Text
            , timestamp_format : Optional Text
            , url : Text
            , user : Text
            }
        )
  , logging_scalyr =
      None (List { name : Text, region : Optional Text, token : Text })
  , logging_sftp =
      None
        ( List
            { address : Text
            , compression_codec : Optional Text
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , password : Optional Text
            , path : Text
            , period : Optional Natural
            , port : Optional Natural
            , public_key : Optional Text
            , secret_key : Optional Text
            , ssh_known_hosts : Text
            , timestamp_format : Optional Text
            , user : Text
            }
        )
  , papertrail = None (List { address : Text, name : Text, port : Natural })
  , s3logging =
      None
        ( List
            { acl : Optional Text
            , bucket_name : Text
            , compression_codec : Optional Text
            , domain : Optional Text
            , gzip_level : Optional Natural
            , message_type : Optional Text
            , name : Text
            , path : Optional Text
            , period : Optional Natural
            , public_key : Optional Text
            , redundancy : Optional Text
            , s3_access_key : Optional Text
            , s3_iam_role : Optional Text
            , s3_secret_key : Optional Text
            , server_side_encryption : Optional Text
            , server_side_encryption_kms_key_id : Optional Text
            , timestamp_format : Optional Text
            }
        )
  , splunk =
      None
        ( List
            { name : Text
            , tls_ca_cert : Optional Text
            , tls_client_cert : Optional Text
            , tls_client_key : Optional Text
            , tls_hostname : Optional Text
            , token : Optional Text
            , url : Text
            }
        )
  , sumologic =
      None (List { message_type : Optional Text, name : Text, url : Text })
  , syslog =
      None
        ( List
            { address : Text
            , message_type : Optional Text
            , name : Text
            , port : Optional Natural
            , tls_ca_cert : Optional Text
            , tls_client_cert : Optional Text
            , tls_client_key : Optional Text
            , tls_hostname : Optional Text
            , token : Optional Text
            , use_tls : Optional Bool
            }
        )
  }
}
