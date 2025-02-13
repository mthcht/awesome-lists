rule Trojan_Win32_Ptredo_YAC_2147900700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ptredo.YAC!MTB"
        threat_id = "2147900700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ptredo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 ec 03 45 e0 0f b6 48 ff 33 d1 8b 45 ec 03 45 e0 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ptredo_YAD_2147900706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ptredo.YAD!MTB"
        threat_id = "2147900706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ptredo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 89 75 40 85 f6 74 33 c7 45 fc 06 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 7d 48 8a 44 1e ff 84 c0 74 ca 30 04 1e eb c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

