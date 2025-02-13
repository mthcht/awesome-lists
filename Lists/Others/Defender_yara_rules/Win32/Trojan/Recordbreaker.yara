rule Trojan_Win32_Recordbreaker_RPZ_2147844109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Recordbreaker.RPZ!MTB"
        threat_id = "2147844109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Recordbreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d8 85 db 0f 84 ca 00 00 00 8b 75 f4 33 c0 6a 01 50 6a 03 50 50 6a 50 58 6a 73 5a 66 3b f2 89 55 ec b9 bb 01 00 00 0f 44 c1 0f b7 c0 50 ff 75 f0 53}  //weight: 1, accuracy: High
        $x_1_2 = {85 db 0f 84 c4 00 00 00 6a 01 33 c0 b9 bb 01 00 00 50 6a 03 50 50 6a 50 58 6a 73 5a 66 39 55 e4 0f 44 c1 0f b7 c0 50 ff 75 ec 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Recordbreaker_RPY_2147850229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Recordbreaker.RPY!MTB"
        threat_id = "2147850229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Recordbreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 11 c1 ea 02 c1 e6 06 8d b4 32 01 07 00 00 8b f8 2b fe 8a 17 88 10 8a 57 01 88 50 01 8a 57 02 41 88 50 02 83 c0 03 8b de 0f b6 79 ff 83 e7 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

