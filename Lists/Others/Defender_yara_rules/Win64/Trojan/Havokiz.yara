rule Trojan_Win64_Havokiz_DX_2147890339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havokiz.DX!MTB"
        threat_id = "2147890339"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 94 03 f0 00 00 00 80 fa ff 75 10 c6 84 03 f0 00 00 00 00 48 83 e8 01 73 e6 eb 0b 48 98 ff c2 88 94 03 f0 00 00 00 31 c0 48 63 d0 ff c0 8a 54 14 30 30 16 48 ff c6 e9}  //weight: 1, accuracy: High
        $x_1_2 = {45 31 d1 44 32 52 ff 41 31 c1 89 c8 01 c9 c0 e8 07 45 31 c8 0f af c7 44 88 42 fe 45 89 d0 44 31 c0 31 c1 88 4a ff 49 39 d3 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Havokiz_SA_2147892307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havokiz.SA!MTB"
        threat_id = "2147892307"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 c0 0f af d0 48 ?? ?? ?? ?? ?? ?? 88 14 01 ff 43 ?? 48 ?? ?? ?? ?? ?? ?? 8b 4b ?? 2b 48 ?? 8b 83 ?? ?? ?? ?? 83 c1 ?? 01 8b ?? ?? ?? ?? 09 05 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 8b 48 ?? 33 8b ?? ?? ?? ?? 83 e9 ?? 09 4b ?? 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Havokiz_PADG_2147901854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havokiz.PADG!MTB"
        threat_id = "2147901854"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 83 fb 0f 48 0f 47 cf 33 d2 48 f7 f6 44 32 04 0a 45 88 01 41 ff c2 4d 8d 49 01 49 63 c2 48 3b ?? ?? ?? ?? ?? 72 d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Havokiz_TI_2147907118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havokiz.TI!MTB"
        threat_id = "2147907118"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 44 24 ?? b8 ?? ?? ?? ?? 48 6b c0 ?? b9 ?? ?? ?? ?? 48 6b c9 ?? 48 8b 54 24 ?? 4c 8b ?? 24 ?? 41 8b 4c 08 ?? 8b 44 02 ?? 0b c1 35 ?? ?? ?? ?? 39 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Havokiz_SA_2147936032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havokiz.SA"
        threat_id = "2147936032"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {17 bd a0 1a 3a ac d0 58}  //weight: 10, accuracy: High
        $x_10_2 = {33 cf 48 d7 a3 ed ba 42}  //weight: 10, accuracy: High
        $x_10_3 = {5b 59 19 59 d9 ed ed 72}  //weight: 10, accuracy: High
        $x_10_4 = {9b 7f 0f 22 8a 5c a2 9e}  //weight: 10, accuracy: High
        $x_10_5 = {55 08 5b 69 d3 dc 65 c8}  //weight: 10, accuracy: High
        $x_10_6 = {86 c7 3f 8a 17 f4 69 a5}  //weight: 10, accuracy: High
        $x_10_7 = {08 d7 ae 94 1f 6e 0a 6e}  //weight: 10, accuracy: High
        $x_10_8 = {ce ce 14 8f d9 ff 2c 66}  //weight: 10, accuracy: High
        $x_10_9 = {04 84 19 23 bf ff 2c 66}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Havokiz_AK_2147936033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havokiz.AK!ibt"
        threat_id = "2147936033"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 56 48 89 ce 53 48 83 ec 20 65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 8b 78 20 48 89 fb 0f b7 53 48 48 8b 4b 50 e8 85 ff ff ff 89 c0 48 39 f0 75 06 48 8b 43 20 eb 11 48 8b 1b 48 85 db 74 05 48 39 df 75 d9 48 83 c8 ff 48 83 c4 20 5b 5e 5f c3 41 57 49 89 d7 41 56 41 55 41 54 55 31 ed 57 56 53 48 89 cb 48 83 ec 28 48 63 41 3c 8b bc 08 88 00 00 00 48 01 cf 44 8b 77 20 44 8b 67 1c 44 8b 6f 24 49 01 ce 3b 6f 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Havokiz_SB_2147936450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havokiz.SB"
        threat_id = "2147936450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {10 48 89 d9 48 8b 59 10 ff 61 08 0f 1f 40 00 49 89 cb c3 49 89 ca 41 8b 43 08 41 ff 23 c3 90 48 c1 e1 04 31 c0 81 e1 f0 0f 00 00 49 01 c8 4c 8d 0c 02 4e 8d 14 00 31 c9 45 8a 1c 0a 48}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

