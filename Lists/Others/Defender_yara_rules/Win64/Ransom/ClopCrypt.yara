rule Ransom_Win64_ClopCrypt_PB_2147765513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ClopCrypt.PB!MTB"
        threat_id = "2147765513"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ClopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "NortonSecurity.exe" wide //weight: 1
        $x_1_2 = "BitDefenderCOM.exe" wide //weight: 1
        $x_10_3 = {4c 0f b7 ee 48 8b 4c 24 ?? e8 63 d2 fc ff 48 8b 4c 24 ?? 48 8b 09 0f b7 d7 c1 ea 08 4a 0f b6 4c 29 ff 32 ca 42 88 4c 28 ff 66 42 0f b6 44 2b ff 66 03 c7 66 69 c0 6d ce 66 81 c0 bf 58 89 c7 66 83 c6 01 66 41 83 ee 01 66 45 85 f6 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_ClopCrypt_PC_2147765514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ClopCrypt.PC!MTB"
        threat_id = "2147765514"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ClopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 84 24 ?? ?? 00 00 48 63 84 24 ?? ?? 00 00 48 3d 52 05 00 00 73 ?? 48 63 84 24 ?? ?? 00 00 48 8d ?? ?? ?? ?? ?? 8b 04 81 89 84 24 ?? ?? 00 00 8b 05 ?? ?? ?? ?? 8b 8c 24 ?? ?? 00 00 33 c8 8b c1 89 84 24 ?? ?? 00 00 8b 84 24 ?? ?? 00 00 c1 c0 07 89 84 24 ?? ?? 00 00 8b 05 ?? ?? ?? ?? 8b 8c 24 ?? ?? 00 00 33 c8 8b c1 89 84 24 ?? ?? 00 00 48 63 84 24 ?? ?? 00 00 48 8b 8c 24 ?? ?? 00 00 8b 94 24 ?? ?? 00 00 89 14 81 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

