rule Trojan_Win64_Cobalt_DF_2147809383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobalt.DF!MTB"
        threat_id = "2147809383"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobalt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 89 4c 24 10 48 8b 54 cc 38 48 83 c2 d0 48 f7 da 48 83 fa 40 48 19 f6 48 89 d1 bf 01 00 00 00 48 d3 e7 48 21 f7 48 89 7c 24 18}  //weight: 10, accuracy: High
        $x_3_2 = "qKguDid" ascii //weight: 3
        $x_3_3 = "CLRWrapper" ascii //weight: 3
        $x_3_4 = "appDomain.Load_3bad" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobalt_AMAB_2147896267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobalt.AMAB!MTB"
        threat_id = "2147896267"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobalt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 ff c0 89 04 24 83 3c 24 21 7d ?? 48 63 04 24 48 8b 4c 24 28 0f be 04 01 89 44 24 04 8b 04 24 99 b9 ?? ?? ?? ?? f7 f9 8b c2 83 c0 32 8b 4c 24 04 33 c8 8b c1 48 63 0c 24 48 8b 54 24 20 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

