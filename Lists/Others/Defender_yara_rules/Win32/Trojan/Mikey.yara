rule Trojan_Win32_Mikey_BK_2147750350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.BK!MSR"
        threat_id = "2147750350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LERKBleRM.pdb" ascii //weight: 1
        $x_1_2 = "developersEesystemsChromeibrowsersz" wide //weight: 1
        $x_2_3 = {8b 44 24 0c 88 c1 88 4c 24 27 c7 44 24 28 00 00 00 00 8a 44 24 27 8b 4c 24 28 8b 54 24 2c 81 f2 [0-4] 8b 74 24 08 88 04 0e 01 d1 89 4c 24 28 8b 54 24 14 39 d1}  //weight: 2, accuracy: Low
        $x_1_4 = {8a 9c 1c 94 00 00 00 8b 7c 24 68 89 4c 24 64 8b 4c 24 74 32 1c 0f 66 89 b4 24 c8 01 00 00 88 1c 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Mikey_SIB_2147814259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.SIB!MTB"
        threat_id = "2147814259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ca 4f be ?? ?? ?? ?? 8a 11 41 84 d2 74 ?? [0-10] 0f be d2 8d 49 01 33 d6 69 f2 ?? ?? ?? ?? 8a 51 ff 84 d2 75 ?? 81 fe ?? ?? ?? ?? 8b 75 ?? 8b 55 ?? ff 75 ?? 8b 46 24 8d 04 78 0f b7 0c 10 8b 46 1c 8d 04 88 8b 04 10 03 c2 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f1 00 89 85 ?? ?? ?? ?? 81 f6 ?? ?? ?? ?? 89 8d ?? ?? ?? ?? 83 f2 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b ca c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b c6 0f a4 c1 ?? c1 e0 ?? 03 f0 89 b5 ?? ?? ?? ?? 13 d1 89 95 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b 95 09 8b b5 0a 8b 85 03 03 d0 8b 8d 05 13 f1 83 c2 ?? 89 95 ?? ?? ?? ?? 83 d6 ?? 89 b5 ?? ?? ?? ?? 8b 85 0b 8b 8d 0d 8b 95 00 8b b5 02 2b d0 89 95 ?? ?? ?? ?? 1b f1 89 b5 ?? ?? ?? ?? 8b b5 1b 8b 95 1c 8b 8d 14 8b 85 16 50 51 52 56 e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8b 8d 22 8b 85 23 8b 45 ?? 30 0c 07 40 89 45 26 3b 45 ?? 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mikey_SPR_2147899899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.SPR!MTB"
        threat_id = "2147899899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "down.0814ok.info:8888/ok.txt" ascii //weight: 2
        $x_1_2 = "down.0814ok.info" ascii //weight: 1
        $x_1_3 = "down10.pdb" ascii //weight: 1
        $x_1_4 = "fuckyoumm2_filter" wide //weight: 1
        $x_1_5 = "select * from __timerevent where timerid=\"fuckyoumm2_itimer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mikey_GZY_2147907437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.GZY!MTB"
        threat_id = "2147907437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 07 8b d0 c1 c2 0f 8b f0 c1 c6 0d 33 d6 c1 e8 0a 33 d0 8b c1 c1 c0 0e 8b f1 c1 ce 07 33 c6 c1 e9 03 33 c1 03 d0 03 57 c8 03 57 ec 89 57 08 01 6c 24 14 66 8b 4c 24 14 8b 44 24 18 0f bf d1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mikey_HNF_2147907539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.HNF!MTB"
        threat_id = "2147907539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {fd 73 9c b1 b9 12 f2 e2 b9 12 f2 e2 b9 12 f2 e2 db 0d e1 e2 bf 12 f2 e2 3a 0e fc e2 b8 12 f2 e2 d6 0d f8 e2 b2 12 f2 e2 d6 0d f6 e2 bb 12 f2 e2 8f 34 f9 e2 bb 12 f2 e2 b9 12 f3 e2 f3 12 f2 e2 8f 34 f6 e2 ba 12 f2 e2 51 0d f9 e2 ba 12 f2 e2 7e 14 f4 e2 b8 12 f2 e2 52 69 63 68 b9 12 f2 e2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 50 45}  //weight: 5, accuracy: High
        $x_5_2 = {60 0d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 30 00 00 34 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 2e 74 65 78 74 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mikey_HNB_2147909116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.HNB!MTB"
        threat_id = "2147909116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00 65 0d a3 87 21 6c cd d4 21 6c cd d4 21 6c cd d4 af 73 de d4 2b 6c cd d4 21 6c cd d4 20 6c cd d4 52 69 63 68 21 6c cd d4 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 50 45 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mikey_HNC_2147909119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.HNC!MTB"
        threat_id = "2147909119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 80 34 39 [0-2] 3b 05 00 [0-4] 8d 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {25 73 25 73 c7 44 24 ?? 25 73 25 73 88 5c 24 04 00 c7 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Mikey_ARA_2147911513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.ARA!MTB"
        threat_id = "2147911513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 08 8a 16 03 c1 30 10 41 3b 4d 0c 7c f1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mikey_ARA_2147911513_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.ARA!MTB"
        threat_id = "2147911513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 54 24 0c 69 d2 d2 f8 62 7e 89 54 24 0c 8a 10 30 11 41 40 3b cf 75 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mikey_NG_2147926319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.NG!MTB"
        threat_id = "2147926319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "R1dNXJMRXwK34kzheoRu 2Y17n0mX40PUEFpdsICbUueMTVlgHVbTmelTX07T2dDSFBJVKo0SMOHKYm=" ascii //weight: 2
        $x_1_2 = "R01AXK5FUcSeKTbffn9q 2S1RG5jeoWka3EaVqIgQVSA4jLqgGZcanGq63V=" ascii //weight: 1
        $x_1_3 = "IWNY11E5dyix3krreHlacSuzTXSpgI0o8W6o11HkLMWr3DKcLh==" ascii //weight: 1
        $x_1_4 = "FisgLns4aOYn30LWLEE8HiRhTHMmLC==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mikey_PGM_2147939518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.PGM!MTB"
        threat_id = "2147939518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {51 6a 01 68 c8 71 40 00 56 ?? ?? d0 ab 40 00 6a 00 8d 95 ec ec ff ff 52 6a 01 68 bc 71 40 00 56 ?? ?? d0 ab 40 00 6a 00 8d 85 ec ec ff ff 50 6a 01 68 b8 71 40 00 56}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mikey_AIV_2147943592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.AIV!MTB"
        threat_id = "2147943592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 0c 1f 8b 55 e8 8b 5d d4 8a 2c 1a 88 2d 55 8b 26 10 88 0d 56 8b 26 10 30 cd 88 2d 54 8b 26 10 c7 05 ?? ?? ?? ?? 4e 0a 00 00 8b 55 e4 88 2c 1a 81 c3 01 00 00 00 8b 55 f0 39 d3 89 5d c8 75 12}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mikey_LMA_2147945892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.LMA!MTB"
        threat_id = "2147945892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {0f be 04 19 41 99 c7 45 fc d9 06 00 00 f7 7d fc 8b c6 c7 45 fc 05 00 00 00 80 c2 4f 30 14 37 33 d2 f7 75 fc f7 da 1b d2 23 ca 46 3b 75 0c}  //weight: 15, accuracy: High
        $x_10_2 = {8b 45 14 8b ce 8b 55 18 83 e1 07 c1 e1 03 e8 ?? ?? ?? ?? 30 04 1e 83 c6 01 83 d7 00 3b 7d 10 72 ?? ?? ?? 3b 75 0c 72 ?? 5f 5e 5b c9 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mikey_AHF_2147949653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.AHF!MTB"
        threat_id = "2147949653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "115"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {4c 89 75 c0 48 c7 45 c8 0e 00 00 00 48 c7 45 d0 0a 00 00 00 4c 89 65 d8 48 c7 45 e0 0a 00 00 00 48 89 7d e8 48 89 5d f0}  //weight: 50, accuracy: High
        $x_30_2 = "src\\modules\\browser\\crypto\\decrypt.rs" ascii //weight: 30
        $x_30_3 = "src\\modules\\browser\\chromium\\crypto\\decrypt.rs" ascii //weight: 30
        $x_20_4 = "src\\modules\\browser\\injection\\injector.rs" ascii //weight: 20
        $x_20_5 = "src\\modules\\browser\\chromium\\injection\\injector.rs" ascii //weight: 20
        $x_10_6 = "Failed to spawn download process for " ascii //weight: 10
        $x_5_7 = "Browser executable not found at registry path" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_30_*) and 2 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_50_*) and 1 of ($x_30_*) and 1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_50_*) and 1 of ($x_30_*) and 2 of ($x_20_*))) or
            ((1 of ($x_50_*) and 2 of ($x_30_*) and 1 of ($x_5_*))) or
            ((1 of ($x_50_*) and 2 of ($x_30_*) and 1 of ($x_10_*))) or
            ((1 of ($x_50_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Mikey_OPQ_2147957695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.OPQ!MTB"
        threat_id = "2147957695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {45 31 ff 45 89 fc 41 83 e4 03 46 8a 64 24 28 47 30 24 3b 4d 8d 67 01 4d 89 e7 4c 39 e1 75 e4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mikey_BAG_2147957887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.BAG!MTB"
        threat_id = "2147957887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {69 64 61 74 61 00 00 00 20 00 00 00 00 04 00 00 02 00 00 00 7e 01}  //weight: 10, accuracy: High
        $x_10_2 = {2e 72 73 72 63 00 00 00 00 20 00 00 00 20 04 00 00 06 00 00 00 80 01}  //weight: 10, accuracy: High
        $x_10_3 = {2e 74 68 65 6d 69 64 61 00 c0 44 00 00 40 04 00 00 00 00 00 00 86 01}  //weight: 10, accuracy: High
        $x_10_4 = {e0 2e 62 6f 6f 74 00 00 00 00 ae 22 00 00 00 49 00 00 ae 22 00 00 86 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mikey_LMJ_2147959696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.LMJ!MTB"
        threat_id = "2147959696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b 85 b8 fc ff ff 99 2b c2 d1 f8 33 c9 85 c0 7e ?? 66 83 b4 4d bc fe ff ff 7c 41 3b c8}  //weight: 20, accuracy: Low
        $x_10_2 = {8b 46 0c 31 03 8b 06 83 e8 15 41 c1 e8 02 83 c3 04 3b c8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mikey_POME_2147959751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mikey.POME!MTB"
        threat_id = "2147959751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 51 ff 83 e2 ?? 0f b6 92 ?? ?? ?? ?? 89 ce 83 e6 ?? 8a b6 ?? ?? ?? ?? 32 54 0f ff 32 34 0f 88 54 08 ff 88 34 08 83 c1 ?? 81 f9 ?? ?? ?? ?? 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

