rule Trojan_Win32_Icedidcrypt_GB_2147775702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Icedidcrypt.GB!MTB"
        threat_id = "2147775702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Icedidcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4e 88 07 8d 5c 1e 09 66 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 44 28 ?? 0f b7 c0 89 44 24 ?? 0f b7 c3 6b c0 ?? 03 05 ?? ?? ?? ?? 47 2b e8 83 5c 24 ?? 00 85 f6 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Icedidcrypt_GC_2147776089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Icedidcrypt.GC!MTB"
        threat_id = "2147776089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Icedidcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b f7 83 c4 0c a2 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 43 46 2b db 46 03 db 83 ee ?? 43 ff d6 3c 00 0f b6 05 ?? ?? ?? ?? 2a 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Icedidcrypt_GD_2147778351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Icedidcrypt.GD!MTB"
        threat_id = "2147778351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Icedidcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 03 41 88 01 4d 03 cd 0f b6 8d ?? ?? ?? ?? 49 03 dd c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 41 03 d5 8b 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 03 c1 89 85 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8b 85}  //weight: 10, accuracy: Low
        $x_10_2 = {03 c2 89 85 ?? ?? ?? ?? 0f b7 85 ?? ?? ?? ?? 8a 4c 04 ?? 42 88 0c 12 89 b5 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 03 c2 41 03 d5 3b 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

