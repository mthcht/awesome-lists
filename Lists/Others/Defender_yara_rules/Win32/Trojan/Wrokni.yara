rule Trojan_Win32_Wrokni_AD_2147735054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wrokni.AD!MTB"
        threat_id = "2147735054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wrokni"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 02 50 b8 ?? ?? ?? ?? ff e0 8b f9 90 58 2b c1 50 b8 ?? ?? ?? ?? ff e0 f7}  //weight: 2, accuracy: Low
        $x_1_2 = {58 8b 4d 08 50 b8 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
        $x_1_3 = {58 03 4d fc 50 b8 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
        $x_1_4 = {58 88 01 50 b8 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wrokni_C_2147735106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wrokni.C"
        threat_id = "2147735106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wrokni"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 64 6c 6c 00 77 6f 72 6b 69 6e 00}  //weight: 10, accuracy: High
        $x_1_2 = {73 65 6c 65 63 74 [0-64] 77 68 65 72 65 20 73 69 67 6e 6f 6e 5f 72 65 61 6c 6d 20 6c 69 6b 65}  //weight: 1, accuracy: Low
        $x_1_3 = {73 65 6c 65 63 74 [0-64] 66 72 6f 6d 20 63 6f 6f 6b 69 65 73 20 77 68 65 72 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

