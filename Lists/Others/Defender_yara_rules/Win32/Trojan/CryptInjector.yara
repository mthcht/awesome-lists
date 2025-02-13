rule Trojan_Win32_CryptInjector_D_2147757480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInjector.D!MTB"
        threat_id = "2147757480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d f4 00 76 30 8b 45 f4 83 e0 03 85 c0 75 15 8b 45 f4 8a 80 ?? ?? ?? ?? 34 ?? 8b 55 fc 03 55 f4 88 02 eb 11 8b 45 f4 8a 80 ?? ?? ?? ?? 8b 55 fc 03 55 f4 88 02 ff 45 f4 81 7d f4 ?? ?? ?? ?? 75 be}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInjector_F_2147757495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInjector.F!MTB"
        threat_id = "2147757495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 76 20 8b c8 83 e1 ?? 85 c9 75 0e 8a 0a 80 f1 ?? 8b 5d fc 03 d8 88 0b eb 09 8b 4d fc 03 c8 8a 1a 88 19 40 42 3d ?? ?? ?? ?? 75 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

