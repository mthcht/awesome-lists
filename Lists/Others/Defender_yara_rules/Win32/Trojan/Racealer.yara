rule Trojan_Win32_Racealer_V_2147746041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.V!MTB"
        threat_id = "2147746041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 1e a2 ?? ?? ?? ?? 0f be 0d ?? ?? ?? ?? 83 e9 14 88 0d ?? ?? ?? ?? 0f be 15 ?? ?? ?? ?? 83 ea 14 88 15 ?? ?? ?? ?? 0f be 05 ?? ?? ?? ?? 83 e8 1e a2}  //weight: 1, accuracy: Low
        $x_1_2 = {03 55 08 8a 82 36 23 01 00 88 01 8b e5 5d c2 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_MSM_2147749910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.MSM!MTB"
        threat_id = "2147749910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f3 07 eb dd 13 81 6c 24 14 52 ef 6f 62 b8 41 e5 64 03 81 6c 24 14 68 19 2a 14 81 44 24 14 be 08 9a 76 8b 4c 24 14 8b 54 24 10}  //weight: 1, accuracy: High
        $x_1_2 = {81 e3 8d 5a 7d 6f c1 e0 04 81 6c 24 14 82 66 52 58 c1 eb 12 81 44 24 14 84 66 52 58 8b 54 24 14 0f af d6 8d 4c 95 00 8b 54 24 1c e8 ?? ?? ?? ?? 46 c7 05 ?? ?? ?? ?? ?? 42 ae 83 3b f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_GA_2147750926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.GA!MTB"
        threat_id = "2147750926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f b6 91 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 d2 b9 00 01 00 00 f7 f1 89 15 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 21 06 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 d0 33 da 8b 45 ?? 03 45 ?? 88 18 8b 4d ?? 83 e9 01 89 4d ?? eb ?? 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_DSK_2147752118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.DSK!MTB"
        threat_id = "2147752118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b cf c1 e9 05 03 4d e4 89 45 fc 89 1d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 8b 45 e0 31 45 fc 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 2, accuracy: Low
        $x_2_2 = {8b cb c1 e9 05 03 4d e0 89 45 fc 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 45 dc 31 45 fc 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 2, accuracy: Low
        $x_2_3 = {8b c7 c1 e8 05 03 45 ?? 03 cb 03 d7 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Racealer_PVS_2147752558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.PVS!MTB"
        threat_id = "2147752558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d d0 03 4d f4 8b 51 08 81 f2 7a ae 00 00 8b 45 d0 03 45 f4 89 50 08}  //weight: 2, accuracy: High
        $x_2_2 = {89 85 c4 f7 ff ff 89 3d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 8b 85 ?? f7 ff ff 31 85 ?? f7 ff ff 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 2, accuracy: Low
        $x_2_3 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 c1 e8 10 30 04 3a 42 3b d6 7c}  //weight: 2, accuracy: High
        $x_2_4 = {0f be 0c 01 89 4d 14 0a 5d 14 f6 d1 0a d1 22 d3 88 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Racealer_PVK_2147753266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.PVK!MTB"
        threat_id = "2147753266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c3 c1 e8 05 03 44 24 ?? 03 d3 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 c7 05 ?? ?? ?? ?? b4 1a 3a df 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 4c 24 ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_MSN_2147753303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.MSN!MTB"
        threat_id = "2147753303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c1 f7 75 08 81 3d ?? ?? ?? ?? bc 09 00 00 8b fa}  //weight: 1, accuracy: Low
        $x_1_2 = {81 e2 ff 00 00 00 0f b6 92 ?? ?? ?? ?? 30 14 37 83 ee 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_DPS_2147753367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.DPS!MTB"
        threat_id = "2147753367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b cb c1 e1 04 03 4c 24 ?? 8b c3 c1 e8 05 03 44 24 ?? 8d 3c 1e 33 cf c7 05 ?? ?? ?? ?? b4 1a 3a df 89 4c 24 10 81 fa 72 07 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_MR_2147753431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.MR!MTB"
        threat_id = "2147753431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/dlc/distribution.php" ascii //weight: 5
        $x_5_2 = "/stats/statistics.php" ascii //weight: 5
        $x_5_3 = "/stats/remember.php" ascii //weight: 5
        $x_5_4 = "/stats/first.php" ascii //weight: 5
        $x_5_5 = "/download.php" ascii //weight: 5
        $x_5_6 = "\\alreadydone.txt" ascii //weight: 5
        $x_1_7 = "/c taskkill /im" ascii //weight: 1
        $x_1_8 = "/f & erase" ascii //weight: 1
        $x_1_9 = "KILLME" ascii //weight: 1
        $x_1_10 = "& exit" ascii //weight: 1
        $x_1_11 = "SOFTOLD" ascii //weight: 1
        $x_1_12 = "Elevated" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 3 of ($x_1_*))) or
            ((6 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Racealer_MR_2147753431_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.MR!MTB"
        threat_id = "2147753431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 c2 03 05 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 25 ?? ?? ?? ?? 8a 98 ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? 88 99 ?? ?? ?? ?? 0f b6 80 ?? ?? ?? ?? 0f b6 cb 03 c1 25 ?? ?? ?? ?? 0f b6 ?? ?? ?? ?? ?? 30 14 3e b8 ?? ?? ?? ?? 29 44 24 ?? 8b 74 24}  //weight: 2, accuracy: Low
        $x_1_2 = {0f b6 c2 03 05 ?? ?? ?? ?? ?? 25 ?? ?? ?? ?? 8a 98 ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? 88 99 ?? ?? ?? ?? 0f b6 ?? ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 0f b6 cb 03 ca 81 e1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8a 81}  //weight: 1, accuracy: Low
        $x_1_3 = {30 04 3e b8 ?? ?? ?? ?? 29 44 24 ?? 8b 74 24 ?? 85 f6 7d}  //weight: 1, accuracy: Low
        $x_2_4 = {0f b6 c2 03 05 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 25 ?? ?? ?? ?? 8a 98 ?? ?? ?? ?? 88 90 01 04 88 99 ?? ?? ?? ?? 0f b6 90 01 04 a3 ?? ?? ?? ?? 0f b6 c3 03 d0 81 e2 ?? ?? ?? ?? 8a 8a ?? ?? ?? ?? 30 0c 37 b8 ?? ?? ?? ?? 29 45 ?? 8b 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Racealer_MX_2147755305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.MX!MTB"
        threat_id = "2147755305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 c1 ea 05 03 54 24 ?? 89 54 24 24 3d 31 09 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c1 2b f0 e8 ?? ?? ?? ?? 8b d6 8b c8 d3 e2 89 6c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_PVD_2147755331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.PVD!MTB"
        threat_id = "2147755331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 e8 05 03 44 24 24 03 ?? 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 c7 05 ?? ?? ?? ?? b4 1a 3a df 89 2d ?? ?? ?? ?? 89 2d ?? ?? ?? ?? 89 4c 24 10 75 02 00 8b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_PVE_2147755364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.PVE!MTB"
        threat_id = "2147755364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c5 c1 e8 05 03 44 24 ?? 03 d5 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 c7 05 ?? ?? ?? ?? b4 1a 3a df 89 1d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 4c 24 10 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_DEA_2147761038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.DEA!MTB"
        threat_id = "2147761038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 d3 e2 8b c8 c1 e9 05 03 8d ?? fd ff ff 03 95 ?? fd ff ff 03 f8 33 d1 33 d7 89 95 ?? fd ff ff 89 35}  //weight: 1, accuracy: Low
        $x_1_2 = "slokadniasdbfiasd" ascii //weight: 1
        $x_1_3 = "faiusdfiasdhgosdfjgos" ascii //weight: 1
        $x_1_4 = "dgosdfjgoisdofgm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Racealer_A_2147776288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.A!MSR"
        threat_id = "2147776288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "S2Y2S2T2E2M2\\2C2o2n2t2r2o2l2S2e2t2020212\\2S2e2r2v2i2c2e2s2\\2D2i2s2k2\\2E2n2u2m2" wide //weight: 2
        $x_1_2 = "sioejfosfse" wide //weight: 1
        $x_1_3 = "jnfiseofsefm" wide //weight: 1
        $x_1_4 = "*.V.I.R.T.U.A.L.*." wide //weight: 1
        $x_1_5 = "TIPOFDAY.TXT" wide //weight: 1
        $x_1_6 = "Qermaxssekfmcskefse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Racealer_RW_2147776533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.RW!MTB"
        threat_id = "2147776533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec 04 08 00 00 a1 ?? ?? ?? ?? 33 c5 89 45 ?? 56 57 33 f6 33 ff 39 75 ?? 7e ?? e8 ?? ?? ?? ?? 30 04 3b 83 7d ?? 19 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_GKM_2147778975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.GKM!MTB"
        threat_id = "2147778975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 74 19 00 00 8b 15 ?? ?? ?? ?? 8a 8c 32 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 88 0c 32 3d 03 02 00 00 75 ?? 6a 00 6a 00 ff d7 a1 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 46 3b f0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_GKM_2147778975_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.GKM!MTB"
        threat_id = "2147778975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 89 55 ?? 8b 45 ?? 01 45 ?? 81 3d ?? ?? ?? ?? c6 0e 00 00 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 4d ?? 33 4d ?? 89 4d ?? 8b 55 ?? 2b 55 ?? 89 55 ?? 8b 45 ?? 29 45 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_GKM_2147778975_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.GKM!MTB"
        threat_id = "2147778975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 89 55 ?? 8b 45 ?? 01 45 ?? 81 3d ?? ?? ?? ?? 8f 0c 00 00 75 ?? 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 4d ?? 33 4d ?? 89 4d ?? 8b 55 ?? 2b 55 ?? 89 55 ?? 8b 45 ?? 29 45 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_MS_2147780896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.MS!MTB"
        threat_id = "2147780896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 33 81 [0-5] 46 3b f7 83 [0-2] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_A_2147782667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.A!MTB"
        threat_id = "2147782667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f0 40 83 f0 06 8b f4 50 68 00 30 00 00 0f b7 0d ?? ?? ?? ?? 81 f1 b9 a6 98 00 83 f1 06 51 6a 00 8b fc ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_B_2147783574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.B!MTB"
        threat_id = "2147783574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 81 c9 00 ff ff ff 41 8a 89 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ec 0f be 11 33 d0 a1 ?? ?? ?? ?? 03 45 ec 88 10 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_B_2147783574_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.B!MTB"
        threat_id = "2147783574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 94 27 27 c7 45 ?? a9 f0 49 67 c7 85 ?? ?? ?? ?? 7a f3 78 2d c7 45 ?? 41 7e 29 56 c7 45 ?? ca 3f 84 06 c7 45 ?? 11 60 50 25 c7 45 ?? 4d 35 a2 53 c7 45 ?? cd 54 42 71 c7 45 ?? f9 b6 59 13}  //weight: 1, accuracy: Low
        $x_1_2 = {46 9e c8 16 c7 45 ?? e7 04 23 11 c7 85 ?? ?? ?? ?? bb d2 3f 34 c7 85 ?? ?? ?? ?? 34 f5 a4 76 c7 45 ?? 3d fc d3 75 c7 45 ?? 97 1e 0c 09 c7 45 ?? 10 00 02 7e c7 85 ?? ?? ?? ?? e5 6f f8 60 c7 45 ?? 4c 68 65 4e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_AK_2147784049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.AK!MTB"
        threat_id = "2147784049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 8c 01 3b 2d 0b 00 8b 15 ?? ?? ?? ?? 88 0c 02 8b 15 ?? ?? ?? ?? 40 3b c2 72 df}  //weight: 10, accuracy: Low
        $x_10_2 = {8a 10 40 3a d3 75 f9 2b c6 3d 15 15 00 00 75 ?? 83 f9 18 75 1c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_C_2147784162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.C!MTB"
        threat_id = "2147784162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 45 fc b8 56 c4 08 00 01 45}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 ec 8b 45 ec 03 45 d4 89 45 ec 8b 45 e4 33 45 f0 89 45 e4 8b 45 e4 33 45 ec 89 45 e4 8b 45 e4 29 45 d0 8b 45 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_F_2147786569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.F!MTB"
        threat_id = "2147786569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e2 04 89 11 c3 8b c1 33 c2 c3 81 01 cc 36 ef c6 c3 29 11 c3 01 11 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b c3 d3 e0 8d [0-37] 8b c3 c1 e8 05 8d [0-37] 33 45 [0-48] b6 0c 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_G_2147787042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.G!MTB"
        threat_id = "2147787042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e2 04 89 11 c3 8b c1 33 c2 c3 81 01 cc 36 ef c6 c3 [0-3] 01 11 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c3 d3 e0 8d [0-37] 8b c3 c1 e8 05 8d [0-37] 33 45 [0-48] b6 0c 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_O_2147793938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.O!MTB"
        threat_id = "2147793938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 cc 36 ef c6 c3 01 08 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8a 94 01 3b 2d 0b 00 88 14 30 40 3b c7 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_O_2147793938_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.O!MTB"
        threat_id = "2147793938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 36 23 01 00 01 45 fc [0-8] 03 55 08 8b 45 fc 03 45 08 8a 08 88 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 fc 04 00 00 00 8b 45 0c 8b 4d fc d3 e0 8b 4d 08 89 01}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 08 8b 08 33 4d 0c 8b 55 08 89 0a}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 08 8b 4d 0c 33 08 8b 55 08 89 0a}  //weight: 1, accuracy: High
        $x_1_5 = {83 e9 14 88 0d ?? ?? ?? ?? 0f be 15 ?? ?? ?? ?? 83 ea 14 88 15 ?? ?? ?? ?? 0f be 05 ?? ?? ?? ?? 83 e8 14 a2 ?? ?? ?? ?? 0f be 0d ?? ?? ?? ?? 83 e9 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_P_2147794232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.P!MTB"
        threat_id = "2147794232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 1e a2 ?? ?? ?? ?? 0f be 0d ?? ?? ?? ?? 83 e9 14 88 0d ?? ?? ?? ?? 0f be 15 ?? ?? ?? ?? 83 ea 14 88 15 ?? ?? ?? ?? 0f be 05 ?? ?? ?? ?? 83 e8 14 a2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 8b 08 33 4d ?? 8b 55 08 89 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_Q_2147794430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.Q!MTB"
        threat_id = "2147794430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 55 8b ec 51 [0-37] 83 65 fc 00 8b 45 08 01 45 fc 8b 45 fc 31 ?? c9 c2 04 00 33 44 24 04 c2 04 00 81 00 ?? 36 ef c6 c3 01 08 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_R_2147794545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.R!MTB"
        threat_id = "2147794545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 1e a2 ?? ?? ?? ?? 0f be 0d ?? ?? ?? ?? 83 e9 14 88 0d ?? ?? ?? ?? 0f be 15 ?? ?? ?? ?? 83 ea 14 88 15 ?? ?? ?? ?? 0f be 05 ?? ?? ?? ?? 83 e8 1e a2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 0c 01 45 fc 8b 45 08 8b 4d fc 33 08 8b 55 08 89 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_S_2147794716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.S!MTB"
        threat_id = "2147794716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 c2 04 00 c1 e0 04 89 01 c3 [0-37] 8b 44 24 04 31 06 c2 04 00 33 44 24 04 c2 04 00 81 00 fe 36 ef c6 c3 01 08 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_T_2147794717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.T!MTB"
        threat_id = "2147794717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 1e a2 ?? ?? ?? ?? 0f be 0d ?? ?? ?? ?? 83 e9 14 88 0d ?? ?? ?? ?? 0f be 15 ?? ?? ?? ?? 83 ea 14 88 15 ?? ?? ?? ?? 0f be 05 ?? ?? ?? ?? 83 e8 1e a2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 f4 c1 e0 04 89 45 e4 [0-48] d3 ea 89 55 ec 8b 45 ec 03 45 d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_PA_2147794787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.PA!MTB"
        threat_id = "2147794787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 00 4e 00 45 00 54 00 47 00 45 00 54 00 20 00 28 00 20 00 22 00 [0-16] 3a 00 2f 00 2f 00 70 00 72 00 6f 00 66 00 65 00 73 00 73 00 6f 00 72 00 6c 00 6f 00 67 00 2e 00 78 00 79 00 7a 00 2f 00 [0-21] 2e 00 7a 00 69 00 70 00 22 00 20 00 2c 00 20 00 22 00 [0-21] 2e 00 7a 00 69 00 70 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {49 4e 45 54 47 45 54 20 28 20 22 [0-16] 3a 2f 2f 70 72 6f 66 65 73 73 6f 72 6c 6f 67 2e 78 79 7a 2f [0-21] 2e 7a 69 70 22 20 2c 20 22 [0-21] 2e 7a 69 70 22 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= OBJCREATE ( \"Shell.Application\" )" ascii //weight: 1
        $x_1_4 = {52 00 55 00 4e 00 20 00 28 00 20 00 22 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 72 00 75 00 6e 00 [0-4] 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = {52 55 4e 20 28 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 72 75 6e [0-4] 2e 65 78 65 22 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Racealer_W_2147795725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.W!MTB"
        threat_id = "2147795725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 [0-48] 31 06 c9 c2 04 00 33 44 24 04 c2 04 00 81 00 fe 36 ef c6 c3 01 08 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {89 55 fc b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_X_2147795726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.X!MTB"
        threat_id = "2147795726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 1e a2 ?? ?? ?? ?? 0f be 0d ?? ?? ?? ?? 83 e9 14 88 0d ?? ?? ?? ?? 0f be 15 ?? ?? ?? ?? 83 ea 14 88 15 ?? ?? ?? ?? 0f be 05 ?? ?? ?? ?? 83 e8 0a a2}  //weight: 1, accuracy: Low
        $x_1_2 = {ec 08 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 88 c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 92 [0-16] c7 45 f8 40 00 00 00 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 7f c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 86 c6 05 ?? ?? ?? ?? 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_Y_2147796249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.Y!MTB"
        threat_id = "2147796249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 1e a2 ?? ?? ?? ?? 0f be 0d ?? ?? ?? ?? 83 e9 14 88 0d ?? ?? ?? ?? 0f be 15 ?? ?? ?? ?? 83 ea 14 88 15 ?? ?? ?? ?? 0f be 05 ?? ?? ?? ?? 83 e8 0a a2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d e4 33 4d f0 89 4d e4 8b 55 ec 33 55 e4 89 55 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_Z_2147796727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.Z!MTB"
        threat_id = "2147796727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 31 08 c3 [0-32] 33 44 24 08 c2 08 00 81 00 fe 36 ef c6 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d6 d3 ea 03 c6 [0-32] 31 45 f8 89 45 ec [0-32] 03 ca c1 ea 05 89 55 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_AA_2147796924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.AA!MTB"
        threat_id = "2147796924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 31 08 c3 81 3d ?? ?? ?? ?? e6 01 00 00 [0-16] 8b 44 24 04 33 44 24 08 c2 08 00 81 00 12 37 ef c6 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d6 d3 ea 03 c6 50 [0-32] 31 45 f4 2b 7d f4 [0-28] 8b c7 c1 e8 05 03 cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_HA_2147797894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.HA!MTB"
        threat_id = "2147797894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 74 24 0c 8b 44 24 08 89 30 5e c2 08 00 33 44 24 04 c2 04 00 81 00 a4 36 ef c6 c3 01 08 c3}  //weight: 1, accuracy: High
        $x_1_2 = {89 55 fc b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_AD_2147815802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.AD!MTB"
        threat_id = "2147815802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 73 24 8b 45 fc 33 d2 f7 75 14 8b 45 08 0f be 0c 10 8b 55 0c 03 55 fc 0f be 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb cb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_DE_2147828955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.DE!MTB"
        threat_id = "2147828955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 6a 00 e8 ?? ?? ?? ?? 8b 5d c8 03 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 31 18 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? bb 04 00 00 00 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 01 5d d8 8b 45 ec 3b 45 d4 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_DF_2147829151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.DF!MTB"
        threat_id = "2147829151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 6a 00 e8 ?? ?? ?? ?? 8b 5d c8 03 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 31 18 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? bb 04 00 00 00 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 01 5d d8 8b 45 ec 3b 45 d4 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_DG_2147829367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.DG!MTB"
        threat_id = "2147829367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 5d b4 6a 00 e8 ?? ?? ?? ?? 8b 5d b4 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_DH_2147829588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.DH!MTB"
        threat_id = "2147829588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8 ?? ?? ?? ?? 8b 55 b4 2b d0 8b 45 ec 31 10 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Racealer_ARAX_2147931745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Racealer.ARAX!MTB"
        threat_id = "2147931745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 5c 02 04 8a 89 30 73 41 00 32 d9 88 5c 02 04 83 c0 05 3d 40 42 0f 00 0f 8c 5b fd ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

