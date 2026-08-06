rule Trojan_Win64_Curlygate_YBB_2147975360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Curlygate.YBB!MTB"
        threat_id = "2147975360"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 10 35 f6 f6 e9 ?? ?? ?? ?? 24 89 81 d4 01 00 00 e9 7b fb ff ff 8b 44 24 08 35 ?? ?? ?? ?? 48 8b 0c 24 89 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Curlygate_YBC_2147975361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Curlygate.YBC!MTB"
        threat_id = "2147975361"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c2 48 8b 45 f0 48 01 d0 8b 4d f8 48 8b 55 f0 48 01 ca 0f b6 00 88 02 8b 45 e0 2b 45 f8 83 e8 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

