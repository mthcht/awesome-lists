rule Ransom_Win32_CylanCrypt_PAA_2147846219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CylanCrypt.PAA!MTB"
        threat_id = "2147846219"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CylanCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e8 02 0f b6 80 ?? ?? ?? ?? 88 06 0f be 4f fb 0f b6 47 fc 83 e1 03 c1 e8 04 c1 e1 04 0b c8 0f b6 81 ?? ?? ?? ?? 88 46 01 0f be 47 fc 0f b6 4f fd 83 e0 0f c1 e0 02 c1 e9 06 0b c8}  //weight: 10, accuracy: Low
        $x_1_2 = "Cylance Ransomware" ascii //weight: 1
        $x_1_3 = "files are encrypted" ascii //weight: 1
        $x_1_4 = "decrypt" ascii //weight: 1
        $x_1_5 = "SELECT * FROM Win32_ShadowCopy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_CylanCrypt_PAB_2147847470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CylanCrypt.PAB!MTB"
        threat_id = "2147847470"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CylanCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b fa 8b ca c1 c7 0f c1 c1 0d 33 f9 c1 ea 0a 33 fa 8b ce 8b d6 c1 c9 07 c1 c2 0e 33 d1 c1 ee 03 33 d6 03 fa}  //weight: 10, accuracy: High
        $x_1_2 = {0f b6 06 8d 76 01 8b ca c1 e2 08 c1 e9 18 33 c8 33 14 8d ?? ?? ?? ?? 83 eb 01 75}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 0e 8d 76 01 8b d0 c1 e0 08 c1 ea 18 33 d1 33 04 95 ?? ?? ?? ?? 83 eb 01 75}  //weight: 1, accuracy: Low
        $x_1_4 = {c1 c8 02 33 d0 8b 45 ?? 8b c8 23 45 ?? 0b 4d ?? 23 4d ?? 0b c8 8b 45 ?? 03 c6 03 ca 03 ce 89 45 ?? 8b f0 89 4d ?? c1 c0 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_CylanCrypt_PAC_2147847471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CylanCrypt.PAC!MTB"
        threat_id = "2147847471"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CylanCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b fa 8b ca c1 c7 0f c1 c1 0d 33 f9 c1 ea 0a 33 fa 8b ce 8b d6 c1 c9 07 c1 c2 0e 33 d1 c1 ee 03 33 d6 03 fa}  //weight: 10, accuracy: High
        $x_1_2 = {0f b6 06 8d 76 01 8b ca c1 e2 08 c1 e9 18 33 c8 33 14 8d ?? ?? ?? ?? 83 eb 01 75}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 0e 8d 76 01 8b d0 c1 e0 08 c1 ea 18 33 d1 33 04 95 ?? ?? ?? ?? 83 eb 01 75}  //weight: 1, accuracy: Low
        $x_1_4 = {0b c8 8b 85 ?? ?? ?? ?? 03 c6 03 ca 03 ce 89 85 ?? ?? ?? ?? 8b f0 89 8d ?? ?? ?? ?? c1 c0 07 8b d1 c1 ce 0b 33 f0 c1 ca 0d 8b 85 ?? ?? ?? ?? c1 c8 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

