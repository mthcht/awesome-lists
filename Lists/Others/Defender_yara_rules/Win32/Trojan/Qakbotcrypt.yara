rule Trojan_Win32_Qakbotcrypt_GA_2147765312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbotcrypt.GA!MTB"
        threat_id = "2147765312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbotcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc f3 a4 50 c7 04 [0-6] 59 ff b3 [0-4] 8f 45 [0-2] ff 75 [0-2] 58 55 81 04 [0-6] 29 2c [0-2] 83 65 [0-2] 00 ff 75 [0-2] 01 04 [0-2] 52 31 14 [0-4] 89 0c [0-4] 8d 83}  //weight: 1, accuracy: Low
        $x_1_2 = {58 59 c7 45 [0-2] 00 00 00 00 ff 75 [0-2] 01 04 [0-2] 8d 83 [0-50] 31 c9 31 c1 89 8b [0-4] 8b 4d [0-2] 31 c0 8b 04 [0-2] 83 ec fc ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbotcrypt_GB_2147765330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbotcrypt.GB!MTB"
        threat_id = "2147765330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbotcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 03 45 [0-2] 8b 0d [0-4] 03 4d [0-2] 03 4d [0-2] 03 4d [0-2] 8b 15 [0-4] 8b 35 [0-4] 8a 04 [0-2] 88 04 [0-2] 8b 0d [0-4] 83 c1 01 89 0d [0-4] eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 31 0d [0-4] c7 05 [0-4] 00 00 00 00 8b 1d [0-4] 01 1d [0-4] a1 [0-4] 8b 0d [0-4] 89 08 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qakbotcrypt_GE_2147778106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbotcrypt.GE!MTB"
        threat_id = "2147778106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbotcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 14 32 88 14 01 a1 ?? ?? ?? ?? 83 c0 01 a3 ?? ?? ?? ?? eb 32 00 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 0d 8b 11 89 15 [0-100] 33 ?? 8b c2 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

