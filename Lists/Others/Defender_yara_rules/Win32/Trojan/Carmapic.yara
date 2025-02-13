rule Trojan_Win32_Carmapic_A_2147632411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carmapic.A"
        threat_id = "2147632411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carmapic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 37 d1 e9 d2 f6 3f 7c 2c 96 a2 eb 96 c8 4e 3b 29 f8 cc 15 ad c7 18 41 56 d6 d3 79 2b 26 97 66 ce 84 30 b7 85 d0 46 16 9b e8 f5 29 73 ac e9 db 53 af 15 80 c3 4c 40 8e 49 cf fc bf cf 46 e0 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Carmapic_C_2147634065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carmapic.C"
        threat_id = "2147634065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carmapic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 00 1e 00 00 00 8b 16 8d 85 28 fe ff ff b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 9d 28 fe ff ff 89 9d 24 fe ff ff 8b 85 24 fe ff ff e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 f8 01 1b c0 40 8b 16 8d 85 20 fe ff ff b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 20 fe ff ff e8 ?? ?? ?? ?? 84 c0 75 aa}  //weight: 1, accuracy: Low
        $x_1_2 = {74 3e 68 f4 01 00 00 e8 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 12 8d 45 f0 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 5d f0 89 5d ec 8b 45 ec e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 f8 01 1b c0 40}  //weight: 1, accuracy: Low
        $x_1_3 = {68 69 64 65 2e 62 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Carmapic_D_2147634593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Carmapic.D"
        threat_id = "2147634593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Carmapic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 37 db a6 6d ec c7 37 43 a0 d0 a1 d2 e4 44 91 4a 6a 72 dc 9a d3 ce 38 1d 71 e7 da 20 16 9e 64 69 b3 23 a6 12 bf 51 2a e5 85 8e 83 34 51 19 c7 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

