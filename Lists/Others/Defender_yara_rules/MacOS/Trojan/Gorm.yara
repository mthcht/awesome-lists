rule Trojan_MacOS_Gorm_HAB_2147956371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Gorm.HAB!MTB"
        threat_id = "2147956371"
        type = "Trojan"
        platform = "MacOS: "
        family = "Gorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "/lib.rsdecodegenerate_secret_key_hvnc::decode/" ascii //weight: 30
        $x_1_2 = "napi_run_scriptnapi_create_async" ascii //weight: 1
        $x_1_3 = "/entry.rs/rustc/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

