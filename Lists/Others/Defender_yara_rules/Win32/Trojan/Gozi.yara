rule Trojan_Win32_Gozi_A_2147735434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.A"
        threat_id = "2147735434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "y:\\s-master\\vcl\\adcs\\release\\LOGESSSS.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_SA_2147739766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.SA!MTB"
        threat_id = "2147739766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c7 80 bb bf 01 [0-16] 89 7d 00 83 c5 04 ff 4c 24 18 bb e0 ff 00 00 [0-16] 89 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_BS_2147740669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.BS!MTB"
        threat_id = "2147740669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 2b c6 83 c0 b5 03 d0 0f b7 c1 03 c7 3d 91 01 00 00 75 0f 8b c6 83 c1 13 2b c2 03 05 ?? ?? ?? ?? 03 c8 8b c6 2b c1 8b 0d ?? ?? ?? ?? 03 c2 83 c2 0e 0f b7 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cf 83 c2 b5 2b c1 03 d0 8d 5a cb 03 d9 89 1d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 44 24 10 04 2b cf 8b 7c 24 14 03 ca ff 4c 24 18 0f b7 c9 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_DSK_2147740750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.DSK!MTB"
        threat_id = "2147740750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {bd a7 19 67 3b 2b ee 89 2d ?? ?? ?? ?? 2b d1 83 c2 50 66 01 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 74 24 10 81 c2 f0 e6 76 01 89 16 81 3d ?? ?? ?? ?? fa ff 00 00 89 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GG_2147742097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GG!MTB"
        threat_id = "2147742097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 28 [0-25] 0f 10 04 31 89 54 24 2c 89 44 24 28 66 8b 5c 24 26 66 81 f3 ?? ?? f3 0f 6f 4c 31 10 66 89 5c 24 26 8b 44 24 18 f3 0f 7f 04 30 8a 44 24 25 b4 ?? f6 e4 88 44 24 25 8b 54 24 18 f3 0f 7f 4c 32 10 83 c6 ?? 8a 44 24 25 0c ?? 88 44 24 25 8b 7c 24 08 39 fe 89 74 24 10 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GN_2147742099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GN!MTB"
        threat_id = "2147742099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c9 03 c0 03 d0 8b c2 8a 35 ?? ?? ?? ?? 13 f9 02 f0 4e 88 35 ?? ?? ?? ?? 0f af f0 8b 4c 24 ?? 8a d3 8b 09 89 4c 24 ?? 8a cb c0 e1 ?? 02 d1 02 d0 88 15 ?? ?? ?? ?? 3b 1d ?? ?? ?? ?? 72 ?? 8d 4b ?? 02 f0 03 c8 88 35}  //weight: 10, accuracy: Low
        $x_1_2 = {f3 a4 8b 44 24 0c 5e 5f c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Gozi_GN_2147742099_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GN!MTB"
        threat_id = "2147742099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 10 33 f6 56 88 95 ?? ?? ?? ?? 53 45 e8}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b6 d3 8d 54 02 ?? 8a c1 b1 ?? f6 e9 f6 db 2a d8 66 0f b6 44 24 ?? 66 0f af c5 66 2b c7 0f b7 c8 8b 06 05 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 02 d1 89 06 80 ea ?? 83 c6 ?? 83 6c 24 ?? 01 a3 ?? ?? ?? ?? 88 54 24 ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GN_2147742099_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GN!MTB"
        threat_id = "2147742099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 0f 6f 01 8b 4c 24 54 0b 4c 24 54 [0-13] 8b 74 24 14 01 ce f3 0f 6f 4a ?? ?? ?? ?? ?? f3 0f 7f 04 ?? 8a 5c 24 63 89 44 24 08 88 d8 ?? ?? ?? ?? 88 44 24 63 8b 4c 24 08 f3 0f 7f 8c 0e ?? ?? ?? ?? 66 8b 7c 24 5a 8b 74 24 40 66 89 7c 24 5a 83 c6 ?? 8b 44 24 54 8b 4c 24 2c 83 f0 ?? 89 44 24 54 89 74 24 3c 39 ce 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_AA_2147742770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.AA"
        threat_id = "2147742770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F:\\fromExe\\EEEEEE\\google_chrome.exe.=,.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_PDSK_2147745108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.PDSK!MTB"
        threat_id = "2147745108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 8b c6 5f 33 cd 25 ff 7f 00 00 5e e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b 8d f8 f3 ff ff 30 04 31 46 3b f7 7c}  //weight: 1, accuracy: High
        $x_2_3 = {8b 54 24 10 81 c7 98 69 cc 01 89 3a 0f b7 05 ?? ?? ?? ?? 0f b7 15 ?? ?? ?? ?? 03 c2 83 f8 17 89 44 24 14 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Gozi_PVD_2147752866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.PVD!MTB"
        threat_id = "2147752866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 28 0f af 05 ?? ?? ?? ?? 8b 8c 24 a0 02 00 00 03 c5 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 88 1c 07 47 3b fe 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 45 c0 0f af 45 bc 2b c8 89 4d b8 8a 45 cc 32 c2 88 45 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_MR_2147753218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.MR!MTB"
        threat_id = "2147753218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 53 57 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 02 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 5b 5d c3 11 00 ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05}  //weight: 1, accuracy: Low
        $x_1_3 = {03 f0 8b 55 ?? 03 32 8b 45 ?? 89 30 8b 4d ?? 8b 11 81 ea ?? ?? ?? ?? 8b 45 ?? 89 10 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_MS_2147753754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.MS!MTB"
        threat_id = "2147753754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 53 57 [0-10] 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 6a ?? ff 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 02 a3 [0-10] 81 e9 [0-18] 81 c1 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 5b 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {03 f0 8b 55 ?? 03 32 8b 45 ?? 89 30 8b 4d ?? 8b 11 81 ea ?? ?? ?? ?? 8b 45 ?? 89 10 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GM_2147756273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GM!MTB"
        threat_id = "2147756273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 2b d0 0f b7 c2 8b 55 ?? 89 45 ?? 0f b7 75 ?? 8d 42 ?? 02 c8 8d 04 b7 88 0d ?? ?? ?? ?? 03 c6 a3 ?? ?? ?? ?? 0f b6 c1 2b c2 83 c0 ?? 89 45 ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GM_2147756273_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GM!MTB"
        threat_id = "2147756273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 8b 55 f0 8b 45 fc 8d 8c 10 ?? ?? ?? ?? 89 4d ?? 8b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 45 ?? a3 ?? ?? ?? ?? 8b 4d ?? 83 c1 ?? 89 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {83 e9 21 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 c1 ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? b8 ?? ?? ?? ?? b8 ?? ?? ?? ?? a1 [0-200] 31 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GM_2147756273_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GM!MTB"
        threat_id = "2147756273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 45 ef 83 e8 ?? 99 03 05 [0-4] 13 15 [0-4] a2 [0-4] 0f b7 05 [0-4] 3d [0-4] 0f b6 45 ?? 83 e8 ?? 99 03 45 ?? 13 55 ?? a3 [0-4] 89 15 [0-4] a1 [0-4] 05 [0-4] a3 [0-4] 8b 0d [0-4] 03 4d ?? 8b 15 [0-4] 89 91 [0-4] a1 [0-4] 83 e8 ?? 33 c9 2b 05 [0-4] 1b 0d [0-4] 88 45 ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RAA_2147756278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RAA!MTB"
        threat_id = "2147756278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 b7 59 e7 1f f7 a4 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 81 84 24 ?? ?? ?? ?? f3 ae ac 68 81 ac 24 ?? ?? ?? ?? b3 30 c7 6b 81 84 24 ?? ?? ?? ?? 21 f4 7c 36 8b 44 24 ?? 30 0c 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RA_2147756499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RA!MTB"
        threat_id = "2147756499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ce 81 c2 d6 04 00 00 8b de 2b ca 2b dd 81 e9 68 da 00 00 83 c3 07 57 8d 3c 00 2b fa 8d 04 49 03 fe c1 e0 04 81 c1 28 c2 01 00 2b c6 05 d6 04 00 00 0f b7 c0 03 c7 03 c6 03 c8 5f 5e 8d 04 29 81 c1 1d e4 00 00 8d 04 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RA_2147756499_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RA!MTB"
        threat_id = "2147756499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 e1 bf 01 00 [0-10] 8a 04 08 88 04 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {bd 00 01 00 00 88 80 78 b7 21 02 40 3b c5 75}  //weight: 1, accuracy: High
        $x_1_3 = {30 04 37 4e 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RA_2147756499_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RA!MTB"
        threat_id = "2147756499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 04 0a 8b f8 85 c0 75 0a c7 44 24 10 01 00 00 00 eb 0d 2b 74 24 0c 03 c6 89 01 8b f7 83 c1 04 ff 4c 24 10 75 da}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d e0 8b 41 0c 2b 41 08 81 45 f8 00 10 00 00 03 41 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RA_2147756499_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RA!MTB"
        threat_id = "2147756499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 ff 75 ?? 57 ff 55 ?? 33 c9 8b f0 39 7d ?? 76 1d 8b c1 99 6a 3c 5f f7 ff 8a 82 ?? ?? ?? ?? 8b 55 ?? 32 04 11 88 04 31 41 3b 4d ?? 72 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RA_2147756499_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RA!MTB"
        threat_id = "2147756499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BFHQdokm.dll" ascii //weight: 1
        $x_1_2 = "AwcN2znPwCc" ascii //weight: 1
        $x_1_3 = "DRGU4KjZapzb9w" ascii //weight: 1
        $x_1_4 = "GSQYOK4RY8ItQ87i" ascii //weight: 1
        $x_1_5 = "H4lzGT8RRUfkbO9" ascii //weight: 1
        $x_1_6 = "XyCkFfBppTpcxg7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GA_2147756532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GA!MTB"
        threat_id = "2147756532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 ?? 00 00 51 6a 00 ff 93 ?? ?? ?? ?? 59 5e 89 83 ?? ?? ?? ?? 89 c7 f3 a4 8b b3 ?? ?? ?? ?? 8d bb ?? ?? ?? ?? 29 f7 01 f8 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GA_2147756532_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GA!MTB"
        threat_id = "2147756532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c0 c8 07 68 cd 1b 02 10 c3}  //weight: 5, accuracy: High
        $x_5_2 = {34 0d 68 98 ec 01 10 c3}  //weight: 5, accuracy: High
        $x_5_3 = {68 2d ad 01 10 68 2d ad 01 10 b8 7c c3 01 10 ff d0}  //weight: 5, accuracy: High
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "VirtualProtectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Gozi_GA_2147756532_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GA!MTB"
        threat_id = "2147756532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 c0 80 e9 ?? 83 c0 ?? 89 35 [0-4] 8b 35 [0-4] 03 c2 89 44 24 ?? 83 c6 cb 8b 03 05 [0-4] 89 03 83 c3 04 a3 [0-4] 8b 44 24 ?? 03 c6 83 6c 24 ?? 01 8b 74 24 ?? 0f b7 c0 89 44 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GA_2147756532_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GA!MTB"
        threat_id = "2147756532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 8b 55 f0 8b 45 fc 8d 8c 10 ?? ?? ?? ?? 89 4d ?? 8b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 45 ?? a3 ?? ?? ?? ?? 8b 4d ?? 83 c1 ?? 89 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ff c7 05 [0-32] 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GA_2147756532_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GA!MTB"
        threat_id = "2147756532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c6 8d 7f 01 03 c1 a3 ?? ?? ?? ?? 8a 44 3b ff 88 47 ff 80 3d ?? ?? ?? ?? 08 8b 15 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 74 ?? c1 e1 ?? 2b ca eb}  //weight: 10, accuracy: Low
        $x_10_2 = {83 c2 f8 0f b7 c0 01 55 ?? 99 85 d2 72 ?? 77 ?? 3b c6 8b 7d 08 ff 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GA_2147756532_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GA!MTB"
        threat_id = "2147756532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c2 49 05 ?? ?? ?? ?? 8a 00 88 82 ?? ?? ?? ?? 42 85 db 77 ?? 72 ?? 83 fe ?? 77}  //weight: 10, accuracy: Low
        $x_10_2 = {8b f0 83 c6 ?? 83 d2 ff 8b 4c 24 ?? 8b 5c 24 ?? 8b 44 24 ?? 03 de a3 ?? ?? ?? ?? 8b 09 89 5c 24 ?? 3b d8 8b 44 24 0c 81 c1 ?? ?? ?? ?? 8b 5c 24 ?? 03 de 89 0d ?? ?? ?? ?? 89 08 83 c0 04 83 6c 24 ?? 01 89 44 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GB_2147756533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GB!MTB"
        threat_id = "2147756533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 8b 4d f0 8b 55 fc 8d 84 0a [0-21] 89 45 ?? 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 55 ?? 89 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ff c7 05 [0-32] 01 05 ?? ?? ?? ?? 8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GB_2147756533_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GB!MTB"
        threat_id = "2147756533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {34 5c 68 62 0c 02 10 c3}  //weight: 5, accuracy: High
        $x_5_2 = {c0 c0 07 68 1b 26 02 10 c3}  //weight: 5, accuracy: High
        $x_5_3 = {68 20 d0 01 10 68 20 d0 01 10 b8 a6 31 02 10 ff d0}  //weight: 5, accuracy: High
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "VirtualProtectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Gozi_GB_2147756533_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GB!MTB"
        threat_id = "2147756533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {99 33 ff 4d 2b c5 1b d7 8b 7c 24 ?? 2b c1 1b d6 8b c8 8b f2 8b c7 05 [0-4] 8a 10 8b 44 24 ?? 88 97 [0-4] 8b d1 2b d0 83 ea 04 0f b7 d2 47}  //weight: 10, accuracy: Low
        $x_10_2 = {2a cb 89 37 80 e9 ?? 83 c7 04 83 6c 24 ?? 01 89 35 ?? ?? ?? ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GB_2147756533_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GB!MTB"
        threat_id = "2147756533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d0 66 89 15 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 54 01 ?? 89 15 ?? ?? ?? ?? 8b 45 ?? 83 e8 ?? 0f b7 0d ?? ?? ?? ?? 2b c1 8b 15 ?? ?? ?? ?? 2b d0 89 15 ?? ?? ?? ?? 8b 75 ?? 81 c2 ?? ?? ?? ?? 83 c6 03 03 d0 83 ee 03 81 ea ?? ?? ?? ?? ff e6}  //weight: 10, accuracy: Low
        $x_10_2 = {64 a1 00 00 00 00 50 83 c4 f0 53 56 57 a1 ?? ?? ?? ?? 31 45 ?? 33 c5 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GC_2147756752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GC!MTB"
        threat_id = "2147756752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b f8 89 bb ?? ?? ?? ?? 83 fb 00 76 [0-30] fc f3 a4 57 c7 04 e4 ff ff 0f 00 59 8b 83 ?? ?? ?? ?? 56 c7 04 e4 ?? ?? ?? ?? 8f 83 ?? ?? ?? ?? 21 8b ?? ?? ?? ?? 01 83 ?? ?? ?? ?? ff a3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GC_2147756752_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GC!MTB"
        threat_id = "2147756752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c8 89 0d ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 4c 02 ?? 89 0d ?? ?? ?? ?? 8b 55 ?? 81 ea ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 41 83 c7 ?? 83 ef ?? 41 ff e7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GC_2147756752_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GC!MTB"
        threat_id = "2147756752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 8b 55 ?? 8b 45 ?? 8d 8c 10 ?? ?? ?? ?? 89 4d ?? 8b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 45 [0-48] 8b 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ff c7 05 ec [0-48] 01 05 [0-48] 8b ff a1 [0-48] 8b 0d [0-37] 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GC_2147756752_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GC!MTB"
        threat_id = "2147756752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 c0 99 33 f6 03 44 24 ?? 13 d6 03 d8 13 ea 8b c7 05 ?? ?? ?? ?? 8a 10 8d 43 ?? 88 97 ?? ?? ?? ?? 0f b7 d0 47 89 54 24 ?? be ?? ?? ?? ?? 66 8b c2 83 3d ?? ?? ?? ?? 30 75}  //weight: 10, accuracy: Low
        $x_10_2 = {89 0e 89 0d ?? ?? ?? ?? 8a ca 02 c8 83 c6 04 83 6c 24 ?? 01 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GC_2147756752_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GC!MTB"
        threat_id = "2147756752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 75 0c 0f af c6 c6 05 ?? ?? ?? ?? 00 69 c0 ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? 8b 7d ?? 81 c3 ?? ?? ?? ?? 83 c7 03 03 d9 83 ef 03 ff d7 4b 00 66 03 0d ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 57 66 89 0d ?? ?? ?? ?? a1}  //weight: 10, accuracy: Low
        $x_10_2 = {64 ff 35 00 00 00 00 [0-12] 2b e0 53 56 57 a1 ?? ?? ?? ?? 31 45 ?? 33 c5 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GD_2147757473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GD!MTB"
        threat_id = "2147757473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 8b 45 ?? 89 45 ?? ff 75 ?? 66 0f b6 05 ?? ?? ?? ?? ba ?? ?? ?? ?? 66 03 c2 0f b7 c8 0f b6 05 ?? ?? ?? ?? 03 c2 8a d0 02 d2 00 15 ?? ?? ?? ?? c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GD_2147757473_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GD!MTB"
        threat_id = "2147757473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b f8 89 bb ?? ?? ?? ?? 83 fb 00 76 [0-30] fc f3 a4 52 c7 04 e4 ff ff 0f 00 ?? 8b 83 ?? ?? ?? ?? 52 81 04 e4 ?? ?? ?? ?? 29 14 e4 8f 83 ?? ?? ?? ?? 21 8b ?? ?? ?? ?? 01 83 ?? ?? ?? ?? ff a3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GD_2147757473_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GD!MTB"
        threat_id = "2147757473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff c7 05 [0-48] 01 1d [0-32] 8b ff a1 [0-16] 8b 0d [0-32] 89 08 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d fc 89 4d f4 8b 15 [0-32] 03 55 ?? 89 15 [0-32] 8b 45 ?? 89 45 ?? 8b 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GD_2147757473_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GD!MTB"
        threat_id = "2147757473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ce 4f 81 c1 ?? ?? ?? ?? 8a 09 88 8e ?? ?? ?? ?? 46 85 d2 77 ?? 72 ?? 83 f8 1e 77}  //weight: 10, accuracy: Low
        $x_10_2 = {2b c2 2b c3 83 c0 ?? 0f b7 d8 8b 06 05 ?? ?? ?? ?? 89 06 83 c6 04 a3 ?? ?? ?? ?? 8b c3 2b 05 ?? ?? ?? ?? 83 e8 08 83 ed 01 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GE_2147757624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GE!MTB"
        threat_id = "2147757624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c2 03 05 ?? ?? ?? ?? 23 c6 a3 ?? ?? ?? ?? 8d 80 ?? ?? ?? ?? 8a 18 88 10 88 19 0f b6 00 0f b6 cb 03 c8 23 ce 8a 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GE_2147757624_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GE!MTB"
        threat_id = "2147757624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fc f3 a4 53 c7 04 e4 ff ff 0f 00 59 ff b3 ?? ?? ?? ?? 8f 45 ?? ff 75 ?? 58 53 c7 04 e4 ?? ?? ?? ?? 8f 83 ?? ?? ?? ?? 21 8b ?? ?? ?? ?? 01 83 ?? ?? ?? ?? ff a3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GE_2147757624_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GE!MTB"
        threat_id = "2147757624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7e ea 00 00 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 d0 b4 07 01 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 15 ?? ?? ?? ?? 89 91 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 69 c8 7e ea 00 00 03 0d ?? ?? ?? ?? 66 89 0d ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GE_2147757624_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GE!MTB"
        threat_id = "2147757624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 e8 be ?? ?? ?? ?? 8d 7d ?? a5 a5 a5 8b 55 ?? 33 55 ?? 8d 71 ?? 03 55 ?? 8b ce 03 55 [0-6] d3 ea 52 8b 55 ?? 8d 0c 02 e8}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 04 0a 8b f8 85 c0 75 [0-10] eb ?? 2b 74 24 ?? 03 c6 89 01 8b f7 83 c1 04 [0-4] 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GE_2147757624_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GE!MTB"
        threat_id = "2147757624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 e8 be ?? ?? ?? ?? 8d 7d ?? a5 a5 a5 8b 55 ?? 33 55 ?? 8d 71 ?? 03 55 ?? 8b ce 03 55 ?? d3 ea 52 8b 55 ?? 8d 0c 02 e8}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 04 0a 85 c0 8b f8 75 ?? 33 db 43 eb ?? 2b 74 24 ?? 03 c6 89 01 8b f7 83 c1 04 4b 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GE_2147757624_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GE!MTB"
        threat_id = "2147757624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 c6 0f b6 ca 2b c8 a1 ?? ?? ?? ?? 83 c0 ?? 03 c1 a3 ?? ?? ?? ?? eb 0a 2a 05 ?? ?? ?? ?? 04 ?? 02 d0 0f b6 c2 81 c7 ?? ?? ?? ?? 66 03 c3 89 3d ?? ?? ?? ?? 66 03 f0 8b 44 24 ?? 83 44 24 ?? 04 66 89 74 24 ?? 89 38 8a 44 24 ?? 8a c8 2a 4c 24 ?? 80 c1 ?? 02 d1 83 6c 24 ?? 01 74}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GF_2147759375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GF!MTB"
        threat_id = "2147759375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f3 2b fe 25 [0-16] 81 6d [0-32] bb ?? ?? ?? ?? 81 45 [0-32] 8b 4d ?? 8b 55 ?? 8b c7 d3 e0 8b cf c1 e9 ?? 03 4d ?? 03 45 ?? 03 d7 33 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GF_2147759375_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GF!MTB"
        threat_id = "2147759375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 0c 4e 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? eb [0-15] 83 25 ?? ?? ?? ?? 00 80 ea ?? 6b c1 ?? 88 15 ?? ?? ?? ?? 2b 45 ?? a3 ?? ?? ?? ?? 0f b6 c2 83 c0 ?? 89 45 ?? ff 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GF_2147759375_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GF!MTB"
        threat_id = "2147759375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 8d 4b ?? 2b c8 1b d6 01 0d [0-4] 8d 48 ff 11 15 [0-4] 0f af d9 8b 4c 24 ?? 8b 39 8a c8 80 e9 ?? 00 0d [0-4] 81 7c 24 [0-5] 75}  //weight: 10, accuracy: Low
        $x_10_2 = {33 c9 2b e8 1b ce 01 2d [0-4] 0f b6 6c 24 ?? 11 0d [0-4] 4d 0f af 2d [0-4] 8b 4c 24 ?? 83 44 24 ?? 04 81 c7 [0-4] 89 39 8a 4c 24 ?? 02 c8 ff 4c 24 ?? 89 2d [0-4] 89 3d [0-4] 88 4c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GF_2147759375_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GF!MTB"
        threat_id = "2147759375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c6 89 75 ?? 29 55 ?? 8d 84 38 ?? ?? ?? ?? 89 55 ?? be ?? ?? ?? ?? 8d 7d ?? a5 a5 a5 8b 55 ?? 33 55 ?? 41 03 55 ?? 89 4d ?? 03 55 ?? d3 ea 85 d2 74}  //weight: 10, accuracy: Low
        $x_10_2 = {2b ca 03 f1 8b 4d ?? 89 37 89 4d ?? 83 c7 04 ff 4d ?? 75}  //weight: 10, accuracy: Low
        $x_1_3 = "2021" ascii //weight: 1
        $x_1_4 = "ConvertStringSecurityDescriptorToSecurityDescriptorA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GF_2147759375_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GF!MTB"
        threat_id = "2147759375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 7d d0 a5 a5 a5 8b 4d ?? 33 4d ?? 68 00 04 00 00 2b 4d ?? 03 4d ?? 8d 4c 11 ?? 8b 55 ?? 51 8d 0c 02 e8 ?? ?? ?? ?? 8b 4d ?? 8b 41 ?? 2b 41 ?? 81 45 ?? 00 10 00 00 03 41 ?? ff 45 ?? a3 ?? ?? ?? ?? 39 5d ?? 72}  //weight: 10, accuracy: Low
        $x_1_2 = "2021" ascii //weight: 1
        $x_1_3 = "ConvertStringSecurityDescriptorToSecurityDescriptorA" ascii //weight: 1
        $x_1_4 = "CreateFileMappingW" ascii //weight: 1
        $x_1_5 = "MapViewOfFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_MX_2147759977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.MX!MTB"
        threat_id = "2147759977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 03 4d ?? 03 45 ?? 33 c1 8b 4d ?? 03 cf 33 c1 29 45 ?? 81 3d ?? ?? ?? ?? d5 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GH_2147775537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GH!MTB"
        threat_id = "2147775537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d7 2b d0 81 c2 ?? ?? ?? ?? 8b c2 6b d2 ?? 8b ee f7 dd 2b ea 03 dd 89 0d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? ba ?? ?? ?? ?? 0f b7 2d ?? ?? ?? ?? 3b cd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GH_2147775537_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GH!MTB"
        threat_id = "2147775537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 6a 05 a1 ?? ?? ?? ?? 50 8b 0d ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 03 f0 8b 15 ?? ?? ?? ?? 2b d6 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 54 01 ?? 88 15 ?? ?? ?? ?? ff 65}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GH_2147775537_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GH!MTB"
        threat_id = "2147775537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 10 88 91 ?? ?? ?? ?? 83 c1 01 33 c0 8d a4 24 00 00 00 00 3b ?? 74}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b6 d0 03 d6 8d 54 1a ?? 8b 5c 24 ?? 89 15 ?? ?? ?? ?? 8a 54 24 ?? 81 c5 ?? ?? ?? ?? 02 d1 80 ea ?? 89 2b 83 c3 ?? 02 c2 83 6c 24 ?? 01 89 2d ?? ?? ?? ?? 89 5c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GR_2147777555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GR!MTB"
        threat_id = "2147777555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 d0 83 c0 ?? 0f b7 c0 89 45 ?? 0f b7 c0 2b c7 89 55 ?? 83 c0 ?? a3 ?? ?? ?? ?? 0f b6 c1 03 c0 2b c6 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GR_2147777555_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GR!MTB"
        threat_id = "2147777555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 2b c3 fe c1 66 83 c0 ?? 02 c9 66 03 f8 8b 44 24 ?? 2a c8 2a cb 8a c1 c0 e1 ?? 02 c1 8b 4c 24 ?? 02 d0 8b 44 24 ?? 88 15 ?? ?? ?? ?? 85 c0 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GR_2147777555_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GR!MTB"
        threat_id = "2147777555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a d9 80 c3 ?? 02 c3 66 0f b6 c8 66 03 ca 8b 16 81 c2 ?? ?? ?? ?? 66 83 c1 ?? 89 16 0f b7 c9 89 15 ?? ?? ?? ?? 8a d1 2a 15 ?? ?? ?? ?? 83 c6 04 80 c2 ?? 02 c2 83 ed 01 8b 15 ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GR_2147777555_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GR!MTB"
        threat_id = "2147777555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 38 8b 44 24 ?? 2b c3 83 c0 ?? 03 c2 3b 05 [0-4] 8d 58 a2 81 c7 [0-4] 8b 44 24 ?? 03 de 89 3d [0-4] 33 c9 89 38 83 c0 04 8b 3d [0-4] 89 44 24 ?? 8d 57 ?? 03 d3 ff 4c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GS_2147777775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GS!MTB"
        threat_id = "2147777775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 d5 00 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8d 4c 11 05 89 0d ?? ?? ?? ?? 8b 8c 37 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 89 8c 37 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8a ca 83 c6 04 80 c1 ?? 81 fe ?? ?? ?? ?? 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GS_2147777775_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GS!MTB"
        threat_id = "2147777775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c2 66 01 35 ?? ?? ?? ?? 89 44 24 ?? a3 ?? ?? ?? ?? 8b 54 24 ?? 83 44 24 ?? 04 8b 02 05 ?? ?? ?? ?? 89 02 8b 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8d 04 49 03 c0 8b cb 2b c8 0f af ce 2b ca 83 6c 24 ?? 01 0f b7 f1 8b 4c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GS_2147777775_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GS!MTB"
        threat_id = "2147777775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c1 8d 52 01 a3 [0-4] 8a 44 17 ff 88 42 ff 8b 35 [0-4] 8d 46 ?? 03 c5 89 44 24 ?? 85 c9 75}  //weight: 10, accuracy: Low
        $x_10_2 = {2b c8 2b ce 89 0d [0-4] 8b 0d [0-4] 8b 84 11 [0-4] 05 [0-4] a3 [0-4] 89 84 11 [0-4] 83 c2 04 a1 [0-4] 8b 35 [0-4] 83 c0 ?? 03 c6 a3 [0-4] 81 fa [0-4] 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GT_2147777882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GT!MTB"
        threat_id = "2147777882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {57 8b 7c 24 ?? 2b fd 8a 04 2f 8d 4a ?? 4e 88 45 00 8b 15 ?? ?? ?? ?? 03 ce 6b c1 ?? 45 6a db 59 2b c8 03 d1 89 15 ?? ?? ?? ?? 85 f6 75 ?? 5f a1 ?? ?? ?? ?? 83 c0 ?? 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GT_2147777882_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GT!MTB"
        threat_id = "2147777882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 45 00 8d 7f 01 88 47 ff 8d 6d ?? 8d 41 ?? 4e 03 c6 0f b7 c8 2b 0d ?? ?? ?? ?? 83 e9 ?? 85 f6 75}  //weight: 10, accuracy: Low
        $x_10_2 = {8d 4a b4 8b b4 07 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? b9 f0 ff ff ff 2b cb 03 d1 8d 8e ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 89 8c 07 ?? ?? ?? ?? 83 c0 04 3d ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GT_2147777882_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GT!MTB"
        threat_id = "2147777882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a d9 0f b6 c0 2a da 8b 15 ?? ?? ?? ?? 03 c7 03 c1 80 eb ?? 89 44 24 ?? 8b 7c 24 ?? a3 ?? ?? ?? ?? a0 ?? ?? ?? ?? 2a 44 24 ?? 2c 04 88 44 24 ?? 89 44 24 ?? a2 ?? ?? ?? ?? 8b c2 2b c1 2b d7}  //weight: 10, accuracy: Low
        $x_10_2 = {89 01 83 c1 ?? a3 ?? ?? ?? ?? 33 c0 83 6c 24 ?? 01 89 44 24 ?? a3 ?? ?? ?? ?? 89 4c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GI_2147779745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GI!MTB"
        threat_id = "2147779745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 89 45 fc 0f b6 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 84 01 ?? ?? ?? ?? a2 ?? ?? ?? ?? 0f b7 45 ?? 83 e8 ?? 2b 45 ?? 0f b7 4d ?? 03 c8 66 89 4d ?? 0f b6 05 ?? ?? ?? ?? 83 e8 ?? a3 ?? ?? ?? ?? ff 65}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GI_2147779745_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GI!MTB"
        threat_id = "2147779745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c2 fd 03 d3 89 15 ?? ?? ?? ?? 8b 10 0f b6 c1 6b c0 ?? 00 05 ?? ?? ?? ?? 3b fb 8d 82 ?? ?? ?? ?? 8b f9 8b 54 24 ?? 81 c7 dc f4 ff ff 83 44 24 ?? 04 a3 ?? ?? ?? ?? 89 02 8b 15 ?? ?? ?? ?? 03 fa 83 6c 24 ?? 01 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GJ_2147779746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GJ!MTB"
        threat_id = "2147779746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 44 01 03 33 c9 a3 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 45 ?? 69 c0 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 2b c1 a2 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 8b 4d ?? 8d 44 08 ?? 89 45 ?? ff 65}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GJ_2147779746_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GJ!MTB"
        threat_id = "2147779746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 18 8b 3d ?? ?? ?? ?? 0f b6 ca 03 ce 8d 73 ?? 03 f1 8a cb c0 e1 ?? 2a cb c0 e1 ?? 2a ca 8a d1 88 15 ?? ?? ?? ?? 83 e8 04 3d ?? ?? ?? ?? 7f}  //weight: 10, accuracy: Low
        $x_10_2 = {89 02 83 c2 04 a3 ?? ?? ?? ?? 8a c1 c0 e0 ?? 02 c1 89 54 24 ?? 8a 0d ?? ?? ?? ?? 02 c0 2a c8 83 6c 24 ?? 01 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GK_2147779747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GK!MTB"
        threat_id = "2147779747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c8 66 89 4d ?? 8b 45 ?? 2d ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 2b c1 89 45 ?? 8b 45 ?? 83 e8 ?? 0f b7 4d ?? 2b c1 66 89 45 ?? 6b 45 ?? ?? 2b 45 ?? a2 ?? ?? ?? ?? ff 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GK_2147779747_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GK!MTB"
        threat_id = "2147779747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c8 8b 44 24 [0-1] 83 c0 d3 03 c1 89 44 24 [0-1] 8b f0 a3 [0-4] 8b 44 24 [0-1] 8a cb 2a 4c 24 [0-1] 81 c7 [0-4] 83 44 24 [0-1] 04 80 c1 [0-1] 89 3d [0-4] 89 38 0f b6 c1 66 0f af c3 66 03 c2 ff 4c 24 [0-1] 8b 54 24 [0-1] 0f b7 d8 89 5c 24 [0-1] 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GL_2147779938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GL!MTB"
        threat_id = "2147779938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c1 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 6b c0 ?? 8b 0d ?? ?? ?? ?? 2b c8 a1 ?? ?? ?? ?? 2b c1 a3 ?? ?? ?? ?? 0f b7 45 ?? 8b 4d ?? 8d 44 08 ?? 66 89 45 ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 44 01 ?? a2 ?? ?? ?? ?? ff 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GL_2147779938_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GL!MTB"
        threat_id = "2147779938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f6 eb 8a d9 2a d8 0f b7 c1 69 c0 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 0f b6 c3 81 c6 ?? ?? ?? ?? 66 8b c8 89 37 66 c1 e0 ?? 83 c7 04 66 03 c8 89 35 ?? ?? ?? ?? 66 03 4c 24 ?? 8d 42 ?? 8b 74 24 ?? 0f b7 c9 02 c1 02 d8 ff 4c 24 ?? 66 8b 44 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GO_2147779993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GO!MTB"
        threat_id = "2147779993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c9 6b c9 ?? 2a d9 8a ca f6 d8 c0 e1 ?? 02 ca 2a c1 02 d8 8b 44 24 ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 84 3d ?? ?? ?? ?? 83 c7 ?? 8b 15 ?? ?? ?? ?? 0f b6 c3 66 83 e8 ?? 66 03 c2 0f b7 c8 89 4c 24 ?? 81 ff ?? ?? ?? ?? 73 ?? a1 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GO_2147779993_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GO!MTB"
        threat_id = "2147779993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 08 88 0a 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 83 c1 ?? 8b 75 ?? 83 d6 00 33 d2 2b 4d ?? 1b f2 0f b7 45 ?? 99 2b c1 1b d6 66 89 45 ?? eb}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b6 45 ff 83 e8 ?? 2b 05 ?? ?? ?? ?? 66 89 45 ?? 8b 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 f4 a1 ?? ?? ?? ?? 89 82 ?? ?? ?? ?? 0f b7 4d ?? 8b 15 ?? ?? ?? ?? 8d 84 0a ?? ?? ?? ?? 66 89 45 ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GP_2147780088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GP!MTB"
        threat_id = "2147780088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f4 8b 0d ?? ?? ?? ?? 83 c0 ?? 83 25 ?? ?? ?? ?? 00 03 c1 0f b7 f0 81 c1 ?? ?? ?? ?? 8b c6 2b 45 ?? 83 e8 ?? a3 ?? ?? ?? ?? 0f b6 c2 8d 04 41 a3 ?? ?? ?? ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GP_2147780088_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GP!MTB"
        threat_id = "2147780088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 ca ba ?? ?? ?? ?? 8b c1 2b 44 24 18 2d ?? ?? ?? ?? 66 39 15 ?? ?? ?? ?? 83 c0 e1 2b cf 03 c8 81 c3 ?? ?? ?? ?? 8b 44 24 ?? 83 44 24 ?? 04 89 0d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 18 8b 44 24 ?? 03 c1 ff 4c 24 ?? 0f b7 d0 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GQ_2147780268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GQ!MTB"
        threat_id = "2147780268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ea 05 2b 15 ?? ?? ?? ?? 66 89 55 ?? 0f b7 45 ?? c1 e0 ?? 2b 45 ?? 33 c9 a3 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? c1 e2 ?? 2b 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? ff 25}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GQ_2147780268_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GQ!MTB"
        threat_id = "2147780268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f2 0f b6 45 ?? 99 03 c1 13 d6 88 45 ?? 8b 15 [0-4] 81 c2 [0-4] 89 15 [0-4] a1 [0-4] 03 45 ?? 8b 0d [0-4] 89 88 [0-4] 0f b7 55 ?? a1 [0-4] 8d 8c 10 [0-4] 0f b6 55 ?? 03 ca 0f b6 45 ?? 03 c1 88 45 ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GEE_2147780322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GEE!MTB"
        threat_id = "2147780322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 e8 be ?? ?? ?? ?? 8d 7d ?? a5 a5 a5 8b 55 ?? 33 55 ?? 8d 71 ?? 03 55 ?? 8b ce 03 55 [0-6] d3 ea 52 8b 55 ?? 8d 0c 02 e8 ?? ?? ?? ?? 8b 4d ?? 8b 41 ?? 2b 41 ?? 81 45 ?? 00 10 00 00 03 41 ?? 8b ce 3b cb a3 ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_10_2 = {03 c6 89 01 8b f7 83 c1 04 [0-4] 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GU_2147780674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GU!MTB"
        threat_id = "2147780674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 04 37 8d 76 01 88 46 ff 4a a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 1b 0d ?? ?? ?? ?? 3d ?? ?? ?? ?? 75 [0-6] a0 ?? ?? ?? ?? 2c 04 02 05 ?? ?? ?? ?? 02 c0 2c 30 a2 ?? ?? ?? ?? 85 d2 75 ?? 8b 2d ?? ?? ?? ?? 8b 44 24 ?? 2b dd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GU_2147780674_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GU!MTB"
        threat_id = "2147780674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4a 8d 76 01 b8 ?? ?? ?? ?? 8d 7f 01 2b c2 03 c8 8a 47 ff 89 0d ?? ?? ?? ?? 88 46 ff 8b 0d ?? ?? ?? ?? 83 c1 ?? 85 d2 75}  //weight: 10, accuracy: Low
        $x_10_2 = {2b c1 8b 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 84 11 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 84 11 ?? ?? ?? ?? b9 0d 00 00 00 a1 ?? ?? ?? ?? 83 c2 04 2b c8 0f b7 c9 81 fa ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GW_2147780745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GW!MTB"
        threat_id = "2147780745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 68 cc f8 00 00 51 8d 50 ?? 50 89 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b cf 33 f6 2b c8 1b f2 89 0d ?? ?? ?? ?? 89 35 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GW_2147780745_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GW!MTB"
        threat_id = "2147780745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 02 88 01 8b 4d ?? 83 c1 01 89 4d}  //weight: 10, accuracy: Low
        $x_10_2 = {03 c1 0f b7 55 ?? 2b c2 a2 ?? ?? ?? ?? 0f b7 45 ?? 83 e8 ?? 99 8b c8 8b f2 2b 4d ?? 1b 75 ?? 0f b6 45 ?? 99 03 c1 13 d6 88 45 ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GY_2147782225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GY!MTB"
        threat_id = "2147782225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {05 8a 1e 01 00 2b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 0f b7 45 f0 8b 4d 0c 8d 44 01 ?? a3 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 44 08 ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 25}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GY_2147782225_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GY!MTB"
        threat_id = "2147782225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 fb 2b 3d ?? ?? ?? ?? 03 7c 24 ?? 89 3d ?? ?? ?? ?? 8b 44 24 ?? 8a d9 2a d8 80 c3 ?? 66 0f b6 d3 66 2b 15 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 66 2b d0 0f b7 c2 89 75 00 83 c5 04 83 6c 24 ?? 01 89 35 ?? ?? ?? ?? 89 44 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GZ_2147782226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GZ!MTB"
        threat_id = "2147782226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c8 66 89 4d ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 44 01 ?? a2 ?? ?? ?? ?? 0f b7 45 ?? 83 e8 0e 2b 45 ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 2b c1 a2 ?? ?? ?? ?? ff 25}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_BA_2147784059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.BA!MTB"
        threat_id = "2147784059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 04 00 00 00 6b c8 12 81 b9 ?? ?? ?? ?? b5 18 00 00 75 42 ba 04 00 00 00 c1 e2 02 [0-48] 81 e9 1d 9b 00 00 0f b6 15 ?? ?? ?? ?? 2b ca 03 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 04 00 00 00 6b d1 09 b8 04 00 00 00 c1 e0 00 [0-21] 81 f9 a4 02 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Noon.dll" ascii //weight: 1
        $x_1_4 = "Closewhether" ascii //weight: 1
        $x_1_5 = "Meantduck" ascii //weight: 1
        $x_1_6 = "Ropemay" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_BB_2147785245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.BB!MTB"
        threat_id = "2147785245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 04 00 00 00 6b d1 14 b8 04 00 00 00 6b c8 06 [0-21] 81 fa dc 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Drive.dll" ascii //weight: 1
        $x_1_3 = "Clockcondition" ascii //weight: 1
        $x_1_4 = "Dogwhen" ascii //weight: 1
        $x_1_5 = "Sing" ascii //weight: 1
        $x_1_6 = "Wholegray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_BB_2147785245_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.BB!MTB"
        threat_id = "2147785245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 63 2b c2 03 ce 83 c0 63 03 c1 a3 ?? ?? ?? ?? a0 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f b6 c8 2a 44 24 10 2b d1 03 da b9 ea 26 00 00 89 1d ?? ?? ?? ?? 04 07 8b 1d ?? ?? ?? ?? 8b b4 3b a4 e8 ff ff 66 39 0d ?? ?? ?? ?? 75 19 0f b7 cd 0f b6 d0 2b d1 8b 0d ?? ?? ?? ?? 83 c1 63 03 ca 89 0d ?? ?? ?? ?? 81 c6 38 84 0b 01 0f b6 c8 89 35 ?? ?? ?? ?? 66 83 c1 63 89 b4 3b a4 e8 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GV_2147793451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GV!MTB"
        threat_id = "2147793451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a d0 2a d6 80 ea ?? 8d 83 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 66 03 f0 89 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 66 89 35 ?? ?? ?? ?? 8a 35 ?? ?? ?? ?? 89 8c 38 ?? ?? ?? ?? 8a c6 2a 05 ?? ?? ?? ?? 83 c7 04 04 ?? 02 d0 a0 ?? ?? ?? ?? 81 ff ?? ?? ?? ?? 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_AO_2147794238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.AO!MTB"
        threat_id = "2147794238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d f4 8d 34 01 33 75 e0 83 e2 1f 33 75 e4 03 f2 56 51 8d 14 38}  //weight: 1, accuracy: High
        $x_1_2 = {33 c1 33 44 24 10 43 8a cb d3 c8 8b ce 89 02 83 c2 04 ff 4c 24 0c 75 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_FF_2147794239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.FF!MTB"
        threat_id = "2147794239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ExperimentersCain" wide //weight: 1
        $x_1_2 = "hulls bathroom vibration" ascii //weight: 1
        $x_1_3 = "ovens multihead Tapes Altos" ascii //weight: 1
        $x_1_4 = "Spacer Aaeon ldapsimplebind supplied purportedly" ascii //weight: 1
        $x_1_5 = "tended fact Byrn yearMonthDuration ISROWID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_B_2147795756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.B!MTB"
        threat_id = "2147795756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 ca 58 55 00 00 0f b7 d1 0f b7 f2 81 c7 08 1a 03 01 2b f0 8b 44 24 18 83 ee 07 89 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_B_2147795756_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.B!MTB"
        threat_id = "2147795756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 2b d7 83 c2 2e 89 15 ?? ?? ?? ?? 3b da 72 31 8b c2 0f af f1 2b c1 83 c3 26 69 ca 30 7b 00 00 03 d8}  //weight: 1, accuracy: Low
        $x_1_2 = "sleep.dll" ascii //weight: 1
        $x_1_3 = "Eggband" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_BC_2147796645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.BC!MTB"
        threat_id = "2147796645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b fa 89 44 24 10 8b 44 24 30 02 db 03 44 24 34 2a df 8b 15 ?? ?? ?? ?? 80 eb 50 8b 74 24 24 2b d0 8b 44 24 28 02 d9 81 3d ?? ?? ?? ?? 21 0b 00 00 89 15 ?? ?? ?? ?? 8b 34 30 75 1c 83 3d ?? ?? ?? ?? 00 75 13 2b 15 ?? ?? ?? ?? 8a da 89 15 ?? ?? ?? ?? 02 db 80 c3 0d 8b 54 24 28 8a c1 2a 44 24 10 81 c6 04 9c 01 01 2c 52 89 35 ?? ?? ?? ?? 02 d8 8b 44 24 24 89 34 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_MB_2147797663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.MB!MTB"
        threat_id = "2147797663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 5d fc 51 8b 4d fc 81 c1 08 00 00 00 89 4d fc 59 d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 f3 [0-21] aa 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_ES_2147797991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.ES!MTB"
        threat_id = "2147797991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 84 24 97 02 00 00 9b 8b 84 24 64 02 00 00 89 c1 83 e9 53 0f 94 c2 8b b4 24 6c 02 00 00 29 c6 0f 94 c6 8b bc 24 90 02 00 00 89 fb 81 c3 d5 9f 04 c4 89 44 24 6c 29 d8 0f 94 c3 81 f7 2d 60 fb 3b 89 44 24 68 8b 44 24 6c 83 e8 03 0f 94 c7 89 74 24 64 66 8b b4 24 ba 00 00 00 66 81 c6 6b 66 39 bc 24 64 02 00 00 89 44 24 60 0f 94 c0 66 89 b4 24 a8 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_NU_2147799632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.NU!MTB"
        threat_id = "2147799632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 6d 4e c6 41 05 39 30 00 00 8b c8 c1 e9 10 81 e1 ff 7f 00 00 81 f9 20 4e 00 00 72 e2 66 0f 6e c1 0f 28 cd f3 0f e6 c0 c1 e9 1f f2 0f 58 04 cd ?? ?? ?? ?? 66 0f 5a c0 0f 5a c0 f2 0f 5e c8 0f 57 c0 f2 0f 5a c1 f3 0f 11 42 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_NT_2147805550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.NT!MTB"
        threat_id = "2147805550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 18 8a 1b 0f b6 ca 80 ea 41 0f b6 fb 80 fa 19 8d 41 20 0f b7 f0 8b c1 0f 47 f0 80 eb 41 8d 47 20 80 fb 19 0f b7 c8 8b c7 0f 47 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_NV_2147805627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.NV!MTB"
        threat_id = "2147805627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 47 20 66 83 ff 61 0f b7 c8 8d 76 02 0f b7 c7 0f 43 c8 69 d2 01 01 00 00 0f b7 c1 03 d0 c1 e0 10 33 d0 0f b7 06 8b f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_NW_2147805841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.NW!MTB"
        threat_id = "2147805841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 43 20 80 fb 61 0f b6 c8 8d 76 01 0f b6 c3 8a 1e 0f 4d c8 69 d2 01 01 00 00 0f be c1 03 d0 c1 e0 10 33 d0 84 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_SIB_2147812544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.SIB!MTB"
        threat_id = "2147812544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MS Shell Dlg 2" wide //weight: 1
        $x_1_2 = "Goetic.dll" ascii //weight: 1
        $x_1_3 = {8b 75 08 8b 7d 0c 8b 55 10 b1 ?? ac 34 ?? [0-16] 04 ?? [0-16] 2a c1 [0-16] 34 ?? [0-5] 2a c1 34 ?? c0 c8 ?? [0-10] 32 c1 2a c1 34 ?? c0 c8 ?? 2a c1 32 c1 04 ?? [0-16] c0 c8 ?? [0-90] aa 4a 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RPQ_2147814410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RPQ!MTB"
        threat_id = "2147814410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fb c3 14 0c 18 89 2d ?? ?? ?? ?? 7c c6 25 00 [0-32] 55 55 55 55 55 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RPR_2147814411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RPR!MTB"
        threat_id = "2147814411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe c3 14 0c 18 89 2d ?? ?? ?? ?? 7c c6 25 00 [0-32] 55 55 55 55 55 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_PAA_2147818356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.PAA!MTB"
        threat_id = "2147818356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 c8 01 f1 81 e1 [0-4] 8b 75 ec 8b 5d d0 8a 1c 1e 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 d0 88 1c 31 8b 4d f0 39 cf 8b 4d c4 89 55 d8 89 4d dc 89 7d d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RPK_2147818499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RPK!MTB"
        threat_id = "2147818499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 c8 8b 36 0f b6 14 16 31 d1 8b 55 bc 8b 32 8b 55 b8 8b 12 88 0c 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_AN_2147818512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.AN!MTB"
        threat_id = "2147818512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b 75 ac 89 16 8b 55 bc 8b 0a 8b 55 c0 8b 12 0f b6 0c 0a 8b 16 8b 75 c8 8b 36 0f b6 14 16 31 d1 8b 55 bc 8b 32 8b 55 b8 8b 12 88 0c 32}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_AN_2147818512_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.AN!MTB"
        threat_id = "2147818512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f b7 c0 6a 19 99 5b f7 fb 80 c2 61 88 14 31 41 3b cf 72 d7}  //weight: 3, accuracy: High
        $x_2_2 = "CoSetProxyBlanket" ascii //weight: 2
        $x_2_3 = "InternetCanonicalizeUrlA" ascii //weight: 2
        $x_2_4 = "GetSidSubAuthorityCount" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_AM_2147819464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.AM!MTB"
        threat_id = "2147819464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {69 f8 6c 00 00 00 89 45 c0 89 f0 01 f8 05 38 00 00 00 8b 7d c0 69 ff 6c 00 00 00}  //weight: 4, accuracy: High
        $x_4_2 = {8b 45 e8 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8 75 e2}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_MA_2147823658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.MA!MTB"
        threat_id = "2147823658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 10 88 14 08 8b d3 ff 05 ?? ?? ?? ?? 8b 4e 64 8b 86 88 00 00 00 c1 ea 08 88 14 01 ff 46 64 8b 0d ?? ?? ?? ?? 8b 81 08 01 00 00 35 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b 89 88 00 00 00 8b 46 64 88 1c 01 ff 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_MA_2147823658_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.MA!MTB"
        threat_id = "2147823658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 75 c8 01 f1 81 e1 ?? ?? ?? ?? 8b 75 ec 8b 5d cc 8a 1c 1e 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 cc 88 1c 31 8b 4d f0 39 cf 8b 4d c4 89 4d dc 89 7d d8 89 55 d4 0f 85}  //weight: 5, accuracy: Low
        $x_1_2 = "FindNextFileA" ascii //weight: 1
        $x_1_3 = "IsWinEventHookInstalled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RPI_2147827451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RPI!MTB"
        threat_id = "2147827451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5d c8 8a 34 1e 32 34 0f 8b 4d d8 88 34 19 8b 4d b8 8b 75 f0 39 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_HQ_2147827647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.HQ!MTB"
        threat_id = "2147827647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Intel\\voiy\\Tyracl.pdb" ascii //weight: 1
        $x_1_2 = "z7ZDthathnshallman.dry" ascii //weight: 1
        $x_1_3 = "beastQLZdSr" ascii //weight: 1
        $x_1_4 = "Whalesvcreatedthat.DividedtherePuponaour" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RC_2147829768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RC!MTB"
        threat_id = "2147829768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 44 01 fd 89 45 fc 8b 75 f0 2b ff 81 ef 75 03 00 00 03 ff ff e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RC_2147829768_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RC!MTB"
        threat_id = "2147829768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 e0 02 c3 0f b6 c8 8b 02 d3 c8 83 c2 04 33 c7 2b c3 89 42 fc 4b 75 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RC_2147829768_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RC!MTB"
        threat_id = "2147829768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 58 14 8b ce 81 f1 0e 15 00 00 42 6b d2 28 03 d8 0f b7 c9 81 f6 5c 5f b2 69 03 da 89 4d f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RC_2147829768_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RC!MTB"
        threat_id = "2147829768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 14 1b 2b d1 81 c2 e4 87 ff ff 0f b6 c2 6b c8 3e 8b c6 89 54 24 14 2b c3 05 e4 87 ff ff 8a d0 89 44 24 10 a3 d4 69 0d 01 2a d1 88 54 24 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RC_2147829768_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RC!MTB"
        threat_id = "2147829768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 d1 8b c8 81 f1 ?? ?? ?? ?? 57 8b 3d ?? ?? ?? ?? 8b 0c 39 03 cf 0f b7 59 ?? 0f b7 71 ?? 43 6b db 28 03 f1 8b ce 8b f0 81 f6 ?? ?? ?? ?? 03 cb 03 f1 35 ?? ?? ?? ?? 89 55 ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RC_2147829768_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RC!MTB"
        threat_id = "2147829768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oLszlG.dll" ascii //weight: 1
        $x_1_2 = "S8DS1Q5xnVIcba" ascii //weight: 1
        $x_1_3 = "UyM9kjYQU85um23g" ascii //weight: 1
        $x_1_4 = "VuKdcUJ8hHQOgha" ascii //weight: 1
        $x_1_5 = "e1wFg3G5NaqO" ascii //weight: 1
        $x_1_6 = "ubJsE4DGnI2zXe" ascii //weight: 1
        $x_1_7 = "ytv4L6uM7hBQGBEm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RF_2147830663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RF!MTB"
        threat_id = "2147830663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d d0 89 4d f0 8b 55 cc 89 55 f8 8b 45 cc 89 45 e0 8b 4d e0 8b 11 33 55 f0 8b 45 e0 89 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RF_2147830663_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RF!MTB"
        threat_id = "2147830663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c1 18 00 00 00 89 45 fc 8b 45 fc 05 c0 00 00 00 05 e0 00 00 00 01 c8 89 45 f8 8b 45 f8 89 45 fc 8b 4d fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RF_2147830663_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RF!MTB"
        threat_id = "2147830663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 fe ff ff 0f b6 ?? 8b 85 04 fe ff ff 99 be ?? 00 00 00 f7 fe 8b 85 64 fe ff ff 0f b6 14 10 33 ca 8b 85 ?? fe ff ff 03 85 ?? fe ff ff 88 08 eb aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RF_2147830663_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RF!MTB"
        threat_id = "2147830663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CT$yhrtgfdr4hery" ascii //weight: 1
        $x_1_2 = "veryDaTsignsy" wide //weight: 1
        $x_1_3 = "won.tkWithoutTwo" wide //weight: 1
        $x_1_4 = "XmanyieldingIztofaceg" wide //weight: 1
        $x_1_5 = "givenincof6Ap" wide //weight: 1
        $x_1_6 = "All7untogHkl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RG_2147830667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RG!MTB"
        threat_id = "2147830667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 06 03 d1 a1 ?? ?? ?? ?? c1 e0 06 03 d0 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? c1 e1 06 2b d1 a1 ?? ?? ?? ?? c1 e0 06 03 d0 8b 0d ?? ?? ?? ?? c1 e1 06 2b d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_R_2147830963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.R!MTB"
        threat_id = "2147830963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "u1DWRtI.dll" ascii //weight: 1
        $x_1_2 = "5b22d1b2c27da3c9a" ascii //weight: 1
        $x_1_3 = "987c15224ade9e93ab7" ascii //weight: 1
        $x_1_4 = "a83150bc76144d859" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RD_2147831804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RD!MTB"
        threat_id = "2147831804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 c9 0d 66 19 00 56 57 bf 5f f3 6e 3c 03 cf 0f b7 c1 69 c9 0d 66 19 00 99 6a 07 5e f7 fe 03 cf 0f b7 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RD_2147831804_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RD!MTB"
        threat_id = "2147831804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c3 c1 ca 05 8b ca d3 c7 8b 4c 24 ?? 2b 31 c1 c8 05 8b c8 33 f8 d3 c6 8b 44 24 ?? 8b 4c 24 ?? 83 e9 08 33 f2 48 89 44 24 ?? 89 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RH_2147832089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RH!MTB"
        threat_id = "2147832089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f6L.dll" ascii //weight: 1
        $x_1_2 = "EGBVpkuesJwBdx" ascii //weight: 1
        $x_1_3 = "JNnvqAKuMpnfRIsc" ascii //weight: 1
        $x_1_4 = "KwjEKqQQZhu" ascii //weight: 1
        $x_1_5 = "PeXPsyizrSgj" ascii //weight: 1
        $x_1_6 = "suNTTChilGGwVeM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RE_2147833343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RE!MTB"
        threat_id = "2147833343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 03 45 fc 0f b6 08 8b 45 fc 99 be 34 00 00 00 f7 fe 8b 45 f4 0f b6 14 10 33 ca 8b 45 f8 03 45 fc 88 08 eb c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RE_2147833343_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RE!MTB"
        threat_id = "2147833343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b 8d 80 ee ff ff 40 0f af 85 6c ee ff ff 03 c6 03 05 ?? ?? ?? ?? 99 f7 bd 74 ee ff ff 8b 85 78 ee ff ff 30 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RE_2147833343_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RE!MTB"
        threat_id = "2147833343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0b 2b 4d 0c 89 45 f8 8b c2 c1 f8 1f 83 c8 ff 2b 45 0c 83 c7 04 83 c3 04 [0-8] 3b c8 76 09 c7 45 0c 01 00 00 00 eb 04 83 65 0c 00 8b 4d f8 29 0e 8b 06 83 ca ff 2b d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RJ_2147837945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RJ!MTB"
        threat_id = "2147837945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d0 b9 30 00 00 00 99 f7 f9 8b 45 f8 8a 14 10 8b 4d d8 8b 45 d0 32 14 01 8b 4d d0 8b 45 fc 88 14 08 ff 45 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RJ_2147837945_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RJ!MTB"
        threat_id = "2147837945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 55 10 33 d2 f7 75 f8 8b 4e 0c 8b 5e 04 03 cf 89 55 ec 85 c0 74 15 8b 39 8b 55 10 83 45 10 04 2b fb 03 df 83 c1 04 48 89 3a 75 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_GFV_2147843194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.GFV!MTB"
        threat_id = "2147843194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 d0 0f b6 30 8b 4d e4 ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 c1 e0 ?? 01 d0 29 c1 89 ca 8b 45 e0 01 d0 0f b6 00 31 f0 88 03 83 45 e4 01 8b 55 e4 8b 45 c4 39 c2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RM_2147843369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RM!MTB"
        threat_id = "2147843369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 71 14 03 f1 8b ce 8b f0 03 cf 81 f6 db 5a 17 43 8b f8 03 f1 89 54 24 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RN_2147843388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RN!MTB"
        threat_id = "2147843388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lift\\Found\\Ocean\\hole\\Hat\\Came\\Holegroup.pdb" ascii //weight: 1
        $x_1_2 = "pressmoment bit determine" ascii //weight: 1
        $x_1_3 = "3crowd log noon can" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RL_2147843682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RL!MTB"
        threat_id = "2147843682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d1 2b d0 2b 54 24 04 8a 12 88 11 ba ff ff ff ff 2b d0 01 54 24 08 8d 4c 01 01 75 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_PAB_2147848284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.PAB!MTB"
        threat_id = "2147848284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 f0 01 29 81 ?? ?? ?? ?? 8b 86 ac 00 00 00 2b 86 d4 00 00 00 8b 0d ?? ?? ?? ?? 2d fb fb 1b 00 01 81 80 00 00 00 8b 8e b4 00 00 00 a1 ?? ?? ?? ?? 31 04 39 83 c7 04 8b 86 8c 00 00 00 33 46 6c 48 09 86}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_MC_2147849936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.MC!MTB"
        threat_id = "2147849936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 75 08 8a 82 ?? ?? ?? ?? 32 04 0f 88 01 8b 45 0c 40 89 45 0c 3b c3 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {89 06 b2 30 8d 42 d0 0f be c8 8b 06 88 14 01 fe c2 80 fa 3a 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Gozi_PAC_2147850233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.PAC!MTB"
        threat_id = "2147850233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 0f 83 c7 04 01 1d ?? ?? ?? ?? 0f af d0 a1 ?? ?? ?? ?? 8b ca c1 e9 08 88 0c 30 8b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 41 89 0d ?? ?? ?? ?? 88 14 08 8b 15 ?? ?? ?? ?? 8b c2 33 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_FS_2147850772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.FS!MTB"
        threat_id = "2147850772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 bb 30 00 00 00 99 f7 fb 8a 82 8c 22 43 00 32 81 2c 61 42 00 8b 55 f8 88 04 0a 41 3b 4d fc 72 de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_DA_2147851102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.DA!MTB"
        threat_id = "2147851102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 42 89 15 ?? ?? ?? ?? c1 e9 ?? 88 0c 10 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 05 a6 14 f6 ff 31 05 ?? ?? ?? ?? 41 a1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 88 1c 08 8b 15 ?? ?? ?? ?? 42 89 15 ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RPY_2147851572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RPY!MTB"
        threat_id = "2147851572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 04 00 00 80 3f c7 04 24 00 00 00 00 ff d0 51 51 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 80 3f c7 04 24 00 00 00 00 ff d6 83 ec 0c c7 44 24 04 00 00 00 bf c7 04 24 52 b8 5e 3f ff 55 80 50 50 c7 44 24 08 00 00 80 3f c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_ME_2147852418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.ME!MTB"
        threat_id = "2147852418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b7 d1 53 8b 1d ?? ?? ?? ?? 56 8b c8 81 f1 ff 5a 17 43 8b 0c 19 03 cb 57 0f b7 79 06 47 8b f0 81 f6 eb 5a 17 43 0f af fe}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_MF_2147852632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.MF!MTB"
        threat_id = "2147852632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 00 8b 12 33 03 89 34 24 89 54 24 04 89 44 24 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_MG_2147887400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.MG!MTB"
        threat_id = "2147887400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af fe 0f b7 71 14 03 f1 8b ce 8b f0 03 cf 81 f6 ?? ?? ?? ?? 8b f8 03 f1 89 55 f0 81 f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_YAA_2147892023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.YAA!MTB"
        threat_id = "2147892023"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 8b 4e 70 89 86 dc 00 00 00 8b 86 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 35 ?? ?? ?? ?? 0f af 86 e8 00 00 00 89 86 e8 00 00 00 8b 46 38 03 46 58 83 f0 4e 01 46 1c 0f b6 c3 0f af d0 8b 86 9c 00 00 00 88 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_YAB_2147892024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.YAB!MTB"
        threat_id = "2147892024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8a 8c 30 ?? ?? ?? ?? 8b c7 25 3f 00 00 80 79 05 48 83 c8 c0 40 8a 98 ?? ?? ?? ?? 68 ?? ?? ?? ?? 32 d9 e8 8c 29 00 00 83 c4 04 8b f0 68 ?? ?? ?? ?? e8 7d 29 00 00 83 c4 04 03 f0 68 ?? ?? ?? ?? e8 6e 29 00 00 83 c4 04 03 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_RPZ_2147892276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.RPZ!MTB"
        threat_id = "2147892276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 18 03 c6 03 c7 83 c4 04 47 88 3c 08 3b 7c 24 10 0f 82 f2 fe ff ff ff 54 24 14 5f 5e 33 c0 5b 8b e5 5d c2 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_KYY_2147921731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.KYY!MTB"
        threat_id = "2147921731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b d1 89 54 24 60 8b 54 24 2c 8b de 8a 04 10 0f af d9 6b db 0f 88 44 24 2b 8d 84 24 ?? ?? ?? ?? 50 2b df e8}  //weight: 5, accuracy: Low
        $x_4_2 = {03 d6 8b 74 24 68 0f b6 c9 03 ca 89 4c 24 3c 8b 54 24 3c 0f b6 c8 0f b7 05 ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 3b c8 0f 4d 54 24 30 8d 46 04 3b f8 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gozi_EAPL_2147929393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gozi.EAPL!MTB"
        threat_id = "2147929393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c1 e8 05 03 44 24 30 33 d0 c7 05 d8 91 4f 00 00 00 00 00 8b 44 24 18 03 c7 33 d0 a1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

