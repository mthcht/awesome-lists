rule Trojan_Win32_TrickbotCrypt_SO_2147762946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotCrypt.SO!MTB"
        threat_id = "2147762946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 3b 4d ?? 0f 83 ?? ?? ?? ?? 8b 45 ?? 83 c0 01 8b 4d ?? 33 d2 f7 31 89 55 ?? 8b 55 ?? 03 55 ?? 33 c0 8a 02 8b 4d ?? 03 c8 8b 75 ?? 8b c1 33 d2 f7 36 89 55 ?? 8b 55 ?? 03 55 ?? 8a 02}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 0a 03 c1 8b 4d ?? 33 d2 f7 31 89 55 ?? 8b 15 ?? ?? ?? ?? 8b 02 8b 4d ?? 33 d2 8a 14 01 8b 45 ?? 03 45 ?? 33 c9 8a 08 33 d1 a1 ?? ?? ?? ?? 8b 08 8b 45 18 88 14 08 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickbotCrypt_NO_2147763122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotCrypt.NO!MTB"
        threat_id = "2147763122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0f 81 e2 ff 00 00 00 03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 8b ea 8b 54 24 ?? 8a 14 10 32 14 29 8b 6c 24 ?? 88 14 28 a1 ?? ?? ?? ?? 40 3b c3 a3 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 8a 14 ?? 8b c3 25 ff 00 00 00 03 ea 03 c5 33 d2 f7 35 ?? ?? ?? ?? 46 47 8b ea 8a 04 29 88 1c 29 88 47 ?? a1 ?? ?? ?? ?? 3b f0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickbotCrypt_NO_2147763122_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotCrypt.NO!MTB"
        threat_id = "2147763122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec ?? 8b 45 ?? 89 45 ?? 8b 4d ?? 89 4d ?? c7 45 f4 00 00 00 00 eb 09 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 3b 45 ?? 73 ?? 8b 4d ?? 03 4d ?? 8b 55 ?? 03 55 ?? 8a 02 88 01 eb ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 4a 14 8d 54 08 ?? 89 55 ?? c7 45 ?? 00 00 00 00 eb ?? 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 83 c1 28 89 4d ?? 8b 55 ?? 8b 02 0f b7 48 06 39 4d ?? 0f 8d}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 f0 83 c2 01 89 55 ?? 8b 45 ?? 83 c0 02 89 45 ?? 8b 4d ?? 8b 51 ?? 83 ea 08 d1 ea 39 55 f0 73 ?? 8b 45 ?? 0f b7 08 c1 f9 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickbotCrypt_SQ_2147763969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotCrypt.SQ!MTB"
        threat_id = "2147763969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 8d 41 ?? f7 f7 6a 00 8b f2 33 d2 89 75 ?? 6a 00 0f b6 04 1e 03 45 ?? f7 f7 0f b6 04 1e 89 55 ?? 8a 0c 1a 88 04 1a 88 0c 1e 0f b6 c1 0f b6 0c 1a 33 d2 03 c1 f7 f7 8b f2 ff 15 ?? ?? ?? ?? 8b 4d ?? 8b 55 ?? 0f b6 04 0a 32 04 1e 88 01 41 ff 4d ?? 89 4d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickbotCrypt_SQ_2147763969_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotCrypt.SQ!MTB"
        threat_id = "2147763969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d3 8b d0 8d 4d ?? ff d6 50 6a ?? ff d3 8b d0 8d 4d ?? ff d6 50 ff d7 8b d0 8d 4d ?? ff d6 50 6a ?? ff d3}  //weight: 2, accuracy: Low
        $x_2_2 = {50 6a 00 e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8d 95 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 52 50 8d 4d ?? 8d 55 ?? 51 8d 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickbotCrypt_SD_2147764058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotCrypt.SD!MTB"
        threat_id = "2147764058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b 74 24 ?? 85 f6 7e ?? 8b 44 24 ?? 8b 4c 24 ?? 2b c8 8a 14 01 80 ea ?? 88 10 83 c0 01 83 ee 01 75 ?? 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 68 01 08 00 00 b9 0b 00 00 00 be ?? ?? ?? ?? 8d 7c 24 ?? 6a 00 f3 a5 ff 15 ?? ?? ?? ?? 8b f0 e8 ?? ?? ?? ?? 85 c0 75 ?? 68 00 08 00 00 56 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickbotCrypt_SE_2147764095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotCrypt.SE!MTB"
        threat_id = "2147764095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 c0 83 c9 ff 8b 7d ?? f2 ae f7 d1 49 89 d8 31 d2 f7 f1 8a 04 16 8b 55 ?? 32 04 1a 8b 55 ?? 88 04 1a ff 05 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 3b 5d ?? 75 ?? 5b 5e 5f 5d c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickbotCrypt_SE_2147764095_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotCrypt.SE!MTB"
        threat_id = "2147764095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 f7 f1 8b 45 ?? 8a 04 38 02 45 0f 8a 0c 3a 02 4d 0f 88 04 3a 8b 45 ?? 88 0c 38 8b c2 0f b6 04 38 0f b6 c9 03 c1 89 55 ?? 33 d2 8b ce f7 f1 8b 4d ?? 03 55 ?? 8a 04 3a 02 45 0f 32 04 19 88 03 43 ff 4d ?? 75}  //weight: 2, accuracy: Low
        $x_1_2 = {ff d6 59 0d 00 10 00 00 50 ff 74 24 ?? 6a 00 ff d7 8b f0 85 f6 74 ?? ff 74 24 ?? 56 6a ?? 68 ?? ?? ?? ?? ff 74 24 ?? 53 ff 54}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickbotCrypt_SV_2147766274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotCrypt.SV!MTB"
        threat_id = "2147766274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 57 56 b8 ?? 00 00 00 89 44 24 ?? b9 ?? ?? ?? ?? 89 4c 24 ?? b8 ?? 00 00 00 89 44 24 ?? 8d 15 ?? ?? ?? ?? 89 14 24 e8 ?? ?? ?? ?? 83 c4 ?? 33 c0 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {53 56 8b 4c 24 ?? 8b 54 24 ?? 8b 74 24 ?? 8b 7c 24 ?? 85 d2 74 ?? ac 52 30 07 5a 4a 47 e2 ?? 5e 5b 33 c0 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickbotCrypt_SV_2147766274_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotCrypt.SV!MTB"
        threat_id = "2147766274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec ?? 68 ?? ?? 00 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 65 6a 00 ff 15 ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 50 6a 00 ff 15 ?? ?? ?? ?? 89 45 ?? 8b 4d ?? 51 6a 00 ff 15 ?? ?? ?? ?? 89 45 ?? 8b 55 ?? 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {75 04 32 c0 eb ?? 8b 4d ?? 8b 11 52 8b 45 ?? 50 8b 4d ?? 51 6a 00 6a 01 6a 00 8b 55 ?? 52 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickbotCrypt_SV_2147766274_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotCrypt.SV!MTB"
        threat_id = "2147766274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ed ff 15 ?? ?? ?? ?? 85 c0 75 ?? 8b 44 24 ?? 6a 40 68 00 10 00 00 50 53 ff 15 ?? ?? ?? ?? 8b e8}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 8b 0d ?? ?? ?? ?? 88 04 01 40 3d ?? ?? 00 00 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c4 04 89 b4 24 ?? ?? 00 00 89 9c 24 ?? ?? 00 00 88 9c 24 ?? ?? 00 00 39 bc 24 ?? ?? 00 00 72 10 8b 8c 24 ?? ?? 00 00 51 e8 ?? ?? 00 00 83 c4 04 89 b4 24 ?? ?? 00 00 89 9c 24 ?? ?? 00 00 88 9c 24 ?? 00 00 00 39 bc 24 ?? 00 00 00 72 ?? 8b 54 24 ?? 52 e8 ?? ?? ?? ?? 83 c4 04 89 b4 24 ?? 00 00 00 89 5c 24 ?? 88 5c 24 ?? 39 bc 24 ?? 00 00 00 72 10 8b 84 24 ?? 00 00 00 50 e8 ?? ?? 00 00 83 c4 04 89 b4 24 ?? 00 00 00 89 9c 24 ?? 00 00 00 88 9c 24 ?? 00 00 00 39 bc 24 ?? ?? 00 00 0f 82 ?? ?? 00 00 8b 8c 24 ?? ?? 00 00 51 e9 ?? ?? 00 00 ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickbotCrypt_SN_2147766802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotCrypt.SN!MTB"
        threat_id = "2147766802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 a3 ?? ?? ?? ?? 33 d2 33 c0 8b 0d ?? ?? ?? ?? 88 04 01 40 3d ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 04 0e 0f b6 da 8b 54 24 ?? 0f b6 14 13 03 d7 03 c2 99 bf ?? ?? 00 00 f7 ff 8a 04 0e 83 c1 02 0f b6 fa 8a 14 37 88 54 0e ?? 88 04 37 8d 2c 37 8d 43 01 99 f7 7c 24 ?? 8b 35 ?? ?? ?? ?? 8b 44 24 ?? 0f b6 da 0f b6 14 03 0f b6 44 0e ?? 03 d7 03 c2 99 bf ?? ?? 00 00 f7 ff 8a 44 0e ?? 0f b6 fa 8a 14 37 8d 2c 37 88 54 0e ?? 88 45 00 8d 43 ?? 99 f7 7c 24 18 81 f9 ?? ?? 00 00 0f 8c}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 54 24 ?? a1 ?? ?? ?? ?? 8a 0c 02 8b 44 24 ?? 30 0c 03 8b 44 24 ?? 43 3b d8 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickbotCrypt_KM_2147772833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotCrypt.KM!MTB"
        threat_id = "2147772833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c2 3b 15 00 00 89 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 2b 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 81 e9 00 f0 0f 0f 89 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 89 0c ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickbotCrypt_SP_2147773313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotCrypt.SP!MTB"
        threat_id = "2147773313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 51 ff d7 8b 95 ?? ?? ?? ?? 50 8b 85 ?? ?? ?? ?? 52 50 e8 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? 8d 95 ?? ?? ?? ?? 51 52 6a 02 8b f0 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {50 51 6a 11 ff 15 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8b 45 ?? 8b 8d ?? ?? ?? ?? 83 c4 ?? 52 50 51 e8 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 01 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickbotCrypt_SS_2147775165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotCrypt.SS!MTB"
        threat_id = "2147775165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 53 6a 00 ff d5 8b 77 ?? 8b d8 8b 44 24 ?? 33 c9 89 44 24 ?? 8b d3 33 c0 89 5c 24 ?? 40 89 44 24 ?? 85 f6 74 ?? 8b 6c 24 ?? 8b 5c 24 ?? 23 e8 4e 85 ed 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c7 2b 44 24 ?? 3b c8 73 ?? 83 f9 3c 72 ?? 83 f9 3e 76 ?? c6 02 00 eb ?? 8a 03 88 02 41 43 42 85 f6 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

