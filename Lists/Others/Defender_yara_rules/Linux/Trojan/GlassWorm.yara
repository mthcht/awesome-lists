rule Trojan_Linux_GlassWorm_HAB_2147956442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/GlassWorm.HAB!MTB"
        threat_id = "2147956442"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "GlassWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_30_1 = ".rsgenerate_secret_key_hvnc::decode" ascii //weight: 30
        $x_1_2 = "napi_run_scriptnapi_create_async" ascii //weight: 1
        $x_1_3 = "/entry.rs/rustc/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

