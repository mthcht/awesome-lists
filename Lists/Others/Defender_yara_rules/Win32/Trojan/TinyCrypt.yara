rule Trojan_Win32_TinyCrypt_A_2147758549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TinyCrypt.A!MTB"
        threat_id = "2147758549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TinyCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 85 ?? ff ff ff 81 bd ?? ff ff ff ?? ?? ?? ?? 0f 83 99 00 00 00 8b 8d ?? ff ff ff 8b 55 ?? 8b 04 8a 89 85 ?? ff ff ff 8b 0d ?? ?? ?? ?? 89 8d ?? ff ff ff 8b 95 ?? ff ff ff 2b 95 ?? ff ff ff 89 95 ?? ff ff ff 8b 45 84 c1 e0 13 89 45 84 8b 8d ?? ff ff ff 33 8d ?? ff ff ff 89 8d ?? ff ff ff 8b 55 84 81 c2 00 00 10 00 89 55 ?? c1 85 ?? ff ff ff 07 8b 45 84 99 81 e2 ff ff 0f 00 03 c2 c1 f8 14 89 45 84 8b 85 ?? ff ff ff 33 85 ?? ff ff ff 89 85 ?? ff ff ff 8b 8d ?? ff ff ff 8b 55 ?? 8b 85 ?? ff ff ff 89 04 8a e9 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = "if exist \"%s\" goto Repeat" ascii //weight: 1
        $x_1_3 = "del  \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TinyCrypt_PA_2147758558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TinyCrypt.PA!MTB"
        threat_id = "2147758558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TinyCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 c8 83 c0 01 89 45 c8 81 7d c8 [0-4] 73 64 8b 4d c8 8b 55 d4 8b 04 8a 89 45 88 8b 0d [0-4] 89 4d 8c 8b 55 88 2b 55 c8 89 55 88 8b 45 e0}  //weight: 1, accuracy: Low
        $x_1_2 = {99 b9 00 00 09 00 f7 f9 89 ?? e0 8b 55 ?? 33 55 ?? 89 55 ?? 8b ?? e0 2d 00 10 00 00 89 ?? e0 c1 45 ?? 07 8b ?? e0 c1 e1 ?? 89 4d e0 8b 55 ?? 33 55 ?? 89 55 ?? 8b 45 ?? 8b 4d f4 8b 55 ?? 89 14 81 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

