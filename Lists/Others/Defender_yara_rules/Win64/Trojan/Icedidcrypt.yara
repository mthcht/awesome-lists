rule Trojan_Win64_Icedidcrypt_GE_2147778606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedidcrypt.GE!MTB"
        threat_id = "2147778606"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedidcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 03 0f b6 8d ?? ?? ?? ?? 41 88 01 c7 85 ?? ?? ?? ?? d3 93 1a 00 8b 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 25 03 00 00 80 41 3b c5 8b 85 ?? ?? ?? ?? 74 ?? 25 03 00 00 80 83 f8 02 8b 85 ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
        $x_10_2 = {25 03 00 00 80 83 f8 03 75 ?? 8b 85 ?? ?? ?? ?? 2b c8 8b 85 ?? ?? ?? ?? [0-8] 4d 03 cd 0f b6 8d ?? ?? ?? ?? c7 85 ?? ?? ?? ?? d3 93 1a 00 8b 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 25 03 00 00 80 41 3b c5 8b 85 ?? ?? ?? ?? 0f 84}  //weight: 10, accuracy: Low
        $x_10_3 = "DllRegisterServer" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedidcrypt_GF_2147778607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedidcrypt.GF!MTB"
        threat_id = "2147778607"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedidcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 03 0f b6 8d ?? ?? ?? ?? 41 88 01 c7 85 ?? ?? ?? ?? c3 ee 4a 00 8b 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 25 03 00 00 80 41 3b c5 8b 85 ?? ?? ?? ?? 74 ?? 25 03 00 00 80 83 f8 02 8b 85 ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
        $x_10_2 = {25 03 00 00 80 83 f8 03 75 ?? 8b 85 ?? ?? ?? ?? 2b c8 8b 85 ?? ?? ?? ?? 0f af c1 89 85 ?? ?? ?? ?? 4d 03 cd 0f b6 8d ?? ?? ?? ?? c7 85 ?? ?? ?? ?? c3 ee 4a 00 8b 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 25 03 00 00 80 41 3b c5 8b 85 ?? ?? ?? ?? 0f 84}  //weight: 10, accuracy: Low
        $x_10_3 = "DllRegisterServer" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedidcrypt_GH_2147778666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedidcrypt.GH!MTB"
        threat_id = "2147778666"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedidcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 03 0f b6 8d ?? ?? ?? ?? 41 88 01 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 25 03 00 00 80 41 3b c5 8b 85 ?? ?? ?? ?? 74 ?? 25 03 00 00 80 83 f8 02 8b 85 ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
        $x_10_2 = {25 03 00 00 80 83 f8 03 75 ?? 8b 85 ?? ?? ?? ?? 2b c8 8b 85 ?? ?? ?? ?? 0f af c1 89 85 ?? ?? ?? ?? 4d 03 cd 0f b6 8d ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 25 03 00 00 80 41 3b c5 8b 85 ?? ?? ?? ?? 0f 84}  //weight: 10, accuracy: Low
        $x_10_3 = "DllRegisterServer" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedidcrypt_GI_2147778802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedidcrypt.GI!MTB"
        threat_id = "2147778802"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedidcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 24 ?? ?? ?? ?? ff c2 0f b6 84 24 ?? ?? ?? ?? 0f b6 84 24 ?? ?? ?? ?? f6 c2 01 75 [0-8] 0f b6 03 41 88 00 49 ff c0 0f b6 84 24 ?? ?? ?? ?? ff c1 0f b6 84 24 ?? ?? ?? ?? 48 ff c3 0f b6 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 3b c8 72}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b6 04 11 88 02 48 ff c2 8b 44 24 ?? ff c0 89 44 24 ?? 8b 44 24 ?? 41 3b c0 72}  //weight: 10, accuracy: Low
        $x_10_3 = "DllRegisterServer" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedidcrypt_GJ_2147778978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedidcrypt.GJ!MTB"
        threat_id = "2147778978"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedidcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d3 30 c3 bb ?? ?? ?? ?? 41 0f 45 dd 84 c0 89 d8 41 0f 45 c5 84 d2 0f 44 c3 eb}  //weight: 10, accuracy: Low
        $x_10_2 = {8d 48 ff 0f af c8 44 31 e1 83 c9 fe 44 39 e1 0f 94 c0 83 fa 0a 0f 9c c3 30 c3}  //weight: 10, accuracy: High
        $x_10_3 = "DllRegisterServer" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedidcrypt_GJ_2147778978_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedidcrypt.GJ!MTB"
        threat_id = "2147778978"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedidcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 00 48 8b 8c 24 ?? ?? ?? ?? 88 01 8a 44 24 ?? 44 89 6c 24 ?? 44 89 6c 24 ?? 0f 57 c0 f2 0f 2a 44 24 ?? f2 0f 11 44 24 ?? 48 8b ac 24 ?? ?? ?? ?? 48 ff c5 8a 44 24 ?? 44 89 6c 24 ?? 44 89 6c 24 ?? 0f 57 c0}  //weight: 10, accuracy: Low
        $x_10_2 = {49 ff c6 8a 44 24 ?? 44 89 6c 24 ?? 44 89 6c 24 ?? 0f 57 c0 f2 0f 2a 44 24 ?? f2 0f 11 44 24 ?? 8b 84 24 ?? ?? ?? ?? 89 44 24 ?? b8 ?? ?? ?? ?? 44 8b 64 24 ?? e9}  //weight: 10, accuracy: Low
        $x_10_3 = "DllRegisterServer" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedidcrypt_GK_2147780478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedidcrypt.GK!MTB"
        threat_id = "2147780478"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedidcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 0a 8a 0f 89 45 00 89 45 04 48 ff c2 48 89 55 ?? 8a 0f 89 45 00 89 45 04 8a 0f 89 45 00 89 45 04 eb}  //weight: 10, accuracy: Low
        $x_10_2 = {41 ff c0 48 8b 4d ?? 44 3b 01 8a 0f 89 45 00 89 45 04 73 ?? 48 ff c3 48 89 5d ?? 8b 0d ?? ?? ?? ?? 44 8b 1d ?? ?? ?? ?? 44 89 d3 e9}  //weight: 10, accuracy: Low
        $x_10_3 = "DllRegisterServer" ascii //weight: 10
        $x_10_4 = "PluginInit" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Icedidcrypt_GL_2147780537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedidcrypt.GL!MTB"
        threat_id = "2147780537"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedidcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 8a 0a 41 88 08 8a 4c 24 ?? 89 54 24 ?? 89 54 24 ?? 49 ff c0 8a 4c 24 ?? 89 54 24 ?? 89 54 24 ?? 8a 4c 24 ?? 89 54 24 ?? 89 54 24 ?? 8b 35 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? eb}  //weight: 10, accuracy: Low
        $x_10_2 = {49 ff c2 ff c5 3b 6c 24 ?? 8a 5c 24 ?? 89 54 24 ?? 89 54 24 ?? 0f 82}  //weight: 10, accuracy: Low
        $x_10_3 = "DllRegisterServer" ascii //weight: 10
        $x_10_4 = "PluginInit" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

