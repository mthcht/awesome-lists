rule Trojan_MacOS_KandyKorn_A_2147899671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/KandyKorn.A!MTB"
        threat_id = "2147899671"
        type = "Trojan"
        platform = "MacOS: "
        family = "KandyKorn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "resp_file_dir" ascii //weight: 1
        $x_1_2 = "resp_cfg_set" ascii //weight: 1
        $x_1_3 = "resp_proc_kill" ascii //weight: 1
        $x_1_4 = "/com.apple.safari.ck" ascii //weight: 1
        $x_1_5 = "curl_easy_getinfo" ascii //weight: 1
        $x_1_6 = "/chkupdate.xxx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_MacOS_KandyKorn_AP_2147918960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/KandyKorn.AP"
        threat_id = "2147918960"
        type = "Trojan"
        platform = "MacOS: "
        family = "KandyKorn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.apple.safari.ck" ascii //weight: 2
        $x_1_2 = "sw_vers" ascii //weight: 1
        $x_1_3 = "/tmp/tempXXXX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

