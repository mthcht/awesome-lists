rule Trojan_Win32_Dreidel_MR_2147772187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dreidel.MR!MTB"
        threat_id = "2147772187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dreidel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 [0-5] 8b [0-6] 01 [0-5] 8b [0-3] c1 [0-3] 03 [0-6] 8d [0-3] 33 [0-5] 81 3d [0-8] c7 05 [0-8] 8b [0-5] 33 [0-5] 89}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 03 [0-5] c7 05 [0-8] 89 [0-5] 33 [0-5] 33 [0-5] 2b [0-3] 8b [0-3] 29 [0-3] ff [0-3] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dreidel_RKQ_2147775269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dreidel.RKQ!MTB"
        threat_id = "2147775269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dreidel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 54 24 ?? 33 d7 33 d6 2b ea 81 3d ?? ?? ?? ?? 17 04 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dreidel_SK_2147902958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dreidel.SK!MTB"
        threat_id = "2147902958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dreidel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {85 c9 7c 29 8b 35 40 90 40 00 b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 03 d2 8b c1 2b c2 8a 90 3c 74 40 00 30 14 0e 41 3b 0d 4c 90 40 00 72 ca a1 40 90 40 00 50 e8 9f bb ff}  //weight: 2, accuracy: High
        $x_2_2 = "&*ygufdksjfsda" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

