rule Trojan_Win32_AresLdrCrypt_LK_2147845746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AresLdrCrypt.LK!MTB"
        threat_id = "2147845746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AresLdrCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 d9 32 14 01 8b 85 ?? ?? ?? ?? 88 14 07 83 85 ?? ?? ?? ff 01 8b 85 ?? ?? ff ff 3b 85 ?? ?? ff ff 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c3 c1 e0 ?? ?? ?? ?? 01 f8 09 d8 0f be da 80 fa ?? ?? ?? ?? 0f 4f de 83 c1 01 0f b6 11 01 d8 84 d2 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_AresLdrCrypt_LKA_2147845747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AresLdrCrypt.LKA!MTB"
        threat_id = "2147845747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AresLdrCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 31 f0 88 03 83 45 e4 01 8b 55 ?? ?? ?? ?? 39 c2 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AresLdrCrypt_LKB_2147845764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AresLdrCrypt.LKB!MTB"
        threat_id = "2147845764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AresLdrCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 8a 84 3a ?? ?? ?? ?? 8b 54 24 ?? 32 04 11 8b 54 24 ?? 88 04 16 47 41 46 3b 7c 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AresLdrCrypt_PBA_2147845889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AresLdrCrypt.PBA!MTB"
        threat_id = "2147845889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AresLdrCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 6b c0 ?? 29 c1 89 c8 89 c2 8b 45 ?? 01 d0 0f b6 00 31 f0 88 03 83 45 e4 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

