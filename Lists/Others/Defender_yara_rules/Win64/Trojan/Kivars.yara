rule Trojan_Win64_Kivars_ARA_2147962575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kivars.ARA!MTB"
        threat_id = "2147962575"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kivars"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 8a c3 41 02 02 32 c1 41 88 02 eb 09}  //weight: 2, accuracy: High
        $x_2_2 = {41 32 0a 41 02 cb 41 88 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Kivars_ARAX_2147962576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kivars.ARAX!MTB"
        threat_id = "2147962576"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kivars"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 63 04 24 48 8b 8c 24 40 01 00 00 0f b6 04 01 0f b6 8c 24 60 01 00 00 03 c1 25 ff 00 00 00 48 63 0c 24 48 8b 94 24 40 01 00 00 88 04 0a 48 63 04 24 0f b6 8c 24 10 01 00 00 48 8b 94 24 40 01 00 00 0f b6 04 02 33 c1 48 63 0c 24 48 8b 94 24 40 01 00 00 88 04 0a eb 49}  //weight: 2, accuracy: High
        $x_2_2 = {48 63 04 24 48 8b 8c 24 40 01 00 00 0f b6 04 01 0f b6 8c 24 10 01 00 00 33 c8 8b c1 88 84 24 10 01 00 00 0f b6 84 24 10 01 00 00 0f b6 8c 24 60 01 00 00 03 c1 25 ff 00 00 00 48 63 0c 24 48 8b 94 24 40 01 00 00 88 04 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

