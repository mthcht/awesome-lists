rule Trojan_Linux_NerbianRAT_K_2147906331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/NerbianRAT.K!MTB"
        threat_id = "2147906331"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "NerbianRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "system_cmd" ascii //weight: 2
        $x_2_2 = "time_flag_change" ascii //weight: 2
        $x_2_3 = "core_config_set" ascii //weight: 2
        $x_1_4 = {48 c7 45 f0 00 00 00 00 ba b6 03 00 00 be 04 00 00 00 bf 07 27 00 00 e8 6f a1 23 00 89 45 ec 83 7d ec ff}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 ec ba 00 00 00 00 be 00 00 00 00 89 c7 e8 08 a1 23 00 48 89 45 f0 48 83 7d f0 ff}  //weight: 1, accuracy: High
        $x_2_6 = {48 8b 45 f0 48 89 45 f8 48 8b 45 f8 8b 00 85 c0 74 18 48 8b 45 f8 8b 00 89 c7 e8 54 5d 23 00 85 c0}  //weight: 2, accuracy: High
        $x_2_7 = {48 8b 45 f0 48 89 c7 e8 be a0 23 00 83 f8 ff 0f 94 c0 84 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

