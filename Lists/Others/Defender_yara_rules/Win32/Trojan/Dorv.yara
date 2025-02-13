rule Trojan_Win32_Dorv_S_2147743009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dorv.S!MTB"
        threat_id = "2147743009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 13 31 16 ad 3b f3 75 f9 e9 ?? ?? ff ff 25 00 8d 35 ?? ?? ?? ?? 8d 1d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dorv_A_2147797739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dorv.A!MTB"
        threat_id = "2147797739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d bd 35 f2 ff ff 88 9d 34 f2 ff ff f3 ab 66 ab aa 8b ce 33 c0 8d bd 2d f0 ff ff 88 9d 2c f0 ff ff f3 ab 66 ab aa 8b ce}  //weight: 10, accuracy: High
        $x_10_2 = {8a d8 8a fb 8b d1 8b c3 c1 e0 10 66 8b c3 5b c1 e9 02 f3 ab}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

