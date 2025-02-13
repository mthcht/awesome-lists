rule Trojan_Win32_Trickbotcrypt_VW_2147769221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbotcrypt.VW!MTB"
        threat_id = "2147769221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbotcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4c 24 ?? 8b [0-5] 8a ?? ?? 8b [0-8] 30 14 [0-6] 3b [0-5] 0f 8c [0-4] 8a ?? ?? ?? 8b ?? ?? ?? 8a ?? ?? ?? ?? ?? ?? 88 [0-10] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbotcrypt_VI_2147771951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbotcrypt.VI!MTB"
        threat_id = "2147771951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbotcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4c 24 [0-1] 8b d5 2b 15 [0-4] 45 03 c2 8b 15 [0-4] 8a 0c [0-1] 04 01 01 01 01 31 32 30 33 ?? 3b 6c [0-2] 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbotcrypt_RTA_2147805282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbotcrypt.RTA!MTB"
        threat_id = "2147805282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbotcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 6b 5d 60 89 4d ?? 8b 45 ?? 89 c1 81 e9 98 f0 68 a4 89 45 ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbotcrypt_RTB_2147805283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbotcrypt.RTB!MTB"
        threat_id = "2147805283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbotcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 9d 63 0f 8b 44 24 ?? 89 c1 81 e9 30 fd 0d 84 89 44 24 ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

