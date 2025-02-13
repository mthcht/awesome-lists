rule TrojanDropper_Win32_Bunitu_C_2147682521_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.C"
        threat_id = "2147682521"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8b c8 8b 41 3c 8b 54 08 78 03 d1 8b 52 1c 8b 14 11 01 14 24 c3}  //weight: 1, accuracy: High
        $x_1_2 = {33 c9 51 50 ff 15 ?? ?? ?? ?? 33 c9 59 ff e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_C_2147682521_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.C"
        threat_id = "2147682521"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 4f 46 54 57 41 52 45 5c 4d 69 ?? ?? ?? ?? 6f 66 74 5c 58 ?? 6e 64 6f 77 73 20 ?? 54 5c 43 75 72 ?? 65 6e 74 56 65 72 73 69 6f 6e 5c}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 01 00 00 80 e8 ?? ?? ?? ?? c7 05 ?? ?? ?? 00 72 75 6e 64 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 2d ?? ?? ?? ?? ?? ?? ?? ?? 66 c7 05 ?? ?? ?? 00 20 22}  //weight: 1, accuracy: Low
        $x_1_3 = {13 81 68 2d ?? ?? ?? ?? (ff|83) [0-1] e8 ?? ?? ?? ?? b8 02 00 00 80 e8 ?? ?? ?? ?? 83 3d ?? ?? ?? 00 02 75 0b 0b c0 75 07}  //weight: 1, accuracy: Low
        $x_1_4 = {8b fa b9 2c 01 00 00 f2 ae 5a 57 c6 47 ff 22 b0 [0-16] 83 c7 01 8d 35 ?? ?? ?? ?? b9 06 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {8b f9 2b cf 0f b6 16 03 c2 46 03 d8 8b [0-10] bf f1 ff 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {d1 e6 87 de ?? c3 4b 75 fb 5b bf ?? ?? ?? ?? 0f 31 (d1 c8|c1)}  //weight: 1, accuracy: Low
        $x_1_7 = {77 49 45 65 ff 4a 84 07 09 e5 9d 81 00 [0-32] a8 cc ee 2d 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {77 49 45 65 ff 4a 84 07 09 e5 9d 81 09 a5 a0 81}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Bunitu_G_2147697071_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.G"
        threat_id = "2147697071"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {87 de 42 42 03 c3 4b 75 fa 5b bf ?? ?? ?? ?? 0f 31 c1 c0 03 50 48 8f 07 0a 00 [0-8] d1 e6}  //weight: 2, accuracy: Low
        $x_2_2 = {8b fa b9 2c 01 00 00 f2 ae 5a 57 c6 47 ff (22|21 fe) b0 [0-16] 83 c7 01 8d 35 ?? ?? ?? ?? b9 06 00 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {13 81 68 2d ?? ?? ?? ?? 83 68 2d 03 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 02 00 00 80 e8 ?? ?? ?? ?? b9 00 00 00 00 83 3d ?? ?? ?? ?? 02 75 0f 3b c1 75 0b}  //weight: 2, accuracy: Low
        $x_1_4 = {50 8b c8 8b 41 3c 8b 54 08 78 03 d1 8b 52 1c 8b 14 11 01 14 24 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Bunitu_J_2147718220_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.J!bit"
        threat_id = "2147718220"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 2a 8b 45 ?? 89 85 ?? ?? ?? ?? 8b 4d ?? 03 8d ?? ?? ?? ?? 8b 55 ?? 03 95 ?? ?? ?? ?? 8a 02 88 01 8b 4d ?? 83 c1 01 89 4d ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 08 8b 11 03 15 ?? ?? ?? ?? 8b 45 08 89 10}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d2 8b c9 8b d2 ba ?? ?? ?? ?? 8b d2 89 55 ?? 8b d2 83 45 ?? ?? 83 45 ?? ?? 83 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_K_2147723145_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.K!bit"
        threat_id = "2147723145"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8b c8 8b 41 3c 8b 54 08 78 03 d1 8b 52 1c 8b 14 11 01 14 24 c3}  //weight: 1, accuracy: High
        $x_2_2 = {8b fa b9 2c 01 00 00 f2 ae 5a 57 c6 47 ff (22|21 fe) b0 [0-16] 83 c7 01 8d 35 ?? ?? ?? ?? b9 06 00 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {03 c6 03 c0 8d 0c 32 81 c1 ?? ?? ?? ?? 83 ea ?? 2b d1 87 ca 81 e9 ?? ?? ?? ?? 2b f9 81 fe}  //weight: 2, accuracy: Low
        $x_1_4 = "advfirewall firewall add rule name=\"Rundll32\" dir=in action=allow protocol=any program=" ascii //weight: 1
        $x_1_5 = "SYSTEM\\ControlSet001\\Services\\MBAMProtector" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Bunitu_Q_2147723146_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.Q!bit"
        threat_id = "2147723146"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c2 01 c1 e2 03 c1 e2 03 8d 04 02 ba ?? ?? ?? ?? 52 8f 00 83 28 08}  //weight: 1, accuracy: Low
        $x_1_2 = {b2 6e 86 d6 88 70 04 b2 65 86 d6 88 70 08 51 b9 ?? ?? ?? ?? 87 d1 29 10 59}  //weight: 1, accuracy: Low
        $x_1_3 = {50 33 f6 81 c6 62 89 03 00 2b 35 ?? ?? ?? ?? bf af 60 00 00 e8 ?? ?? ?? ?? 66 03 c2 c1 e8 10 05 82 0e 00 00 83 c0 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_XD_2147732006_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.XD"
        threat_id = "2147732006"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc 87 4d fc 33 4d fc 87 4d fc 8b 45 fc c7 05 d8 ee 44 00 00 00 00 00 8b c8 01 0d d8 ee 44 00 a1 f0 ee 44 00 8b 0d d8 ee 44 00 89 08}  //weight: 1, accuracy: High
        $x_1_2 = {b8 02 30 00 00 48 48 50 ff ?? ?? ff ?? ?? ff 35 ?? ?? ?? ?? 5a 68 ?? ?? ?? 00 52 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c0 7b 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 66 89 44 4a 14}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c0 7d 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 66 89 44 4a 5e}  //weight: 1, accuracy: Low
        $x_1_5 = {ba 52 14 40 00 83 ea 02 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Bunitu_BS_2147751630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.BS!MTB"
        threat_id = "2147751630"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e9 03 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {81 e9 09 b5 00 00 51 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_BS_2147751630_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.BS!MTB"
        threat_id = "2147751630"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 03 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 06 00 00 00 85 d2 74 ?? a1 ?? ?? ?? ?? 3b 45 ?? 72 ?? eb ?? 8b 4d ?? 03 0d ?? ?? ?? ?? c6 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_BS_2147751630_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.BS!MTB"
        threat_id = "2147751630"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 03 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 06 6a 06 e8 ?? ?? ?? ?? 83 c4 08 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 2d ?? ?? ?? ?? 02 b8 69 00 00 00 8b 0d ?? ?? ?? ?? 66 89 01 ba 65 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_BA_2147752687_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.BA!MTB"
        threat_id = "2147752687"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 03 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {81 e9 09 b5 00 00 51 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_BD_2147752834_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.BD!MTB"
        threat_id = "2147752834"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ea 03 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {81 e9 09 b5 00 00 51 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_MR_2147752877_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.MR!MTB"
        threat_id = "2147752877"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e 8b e5 5d c3 1e 00 03 05 ?? ?? ?? ?? 0f be ?? 30 f7 ?? 8b ?? f8 0f be ?? 2b ?? 8b ?? f8 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_MS_2147753135_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.MS!MTB"
        threat_id = "2147753135"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 11 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 8f 05 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 89 15 [0-172] 33 3d [0-172] 8b cf 8b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 5e 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = "interface\\{" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_2147753613_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.MT!MTB"
        threat_id = "2147753613"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 11 89 15 ?? ?? ?? ?? 8b 15 [0-15] 8f 05 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 89 15 [0-172] 33 [0-172] 8b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f [0-1] 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = "interface\\{" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_MU_2147753629_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.MU!MTB"
        threat_id = "2147753629"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 83 ec ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 33 d7 8b ca 8b c1 c7 45 ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 4d ?? 89 08 5f 8b e5 5d c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_MV_2147753751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.MV!MTB"
        threat_id = "2147753751"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 11 5f 8b e5 5d c3 3c 00 50 8f 05 ?? ?? ?? ?? 8b 3d [0-15] 33 05 ?? ?? ?? ?? 8b [0-4] 89 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_MW_2147754008_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.MW!MTB"
        threat_id = "2147754008"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 da 8b 45 ?? 0f be 08 2b ca 8b 55 00 88 0a 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_MX_2147754424_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.MX!MTB"
        threat_id = "2147754424"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 33 05 ?? ?? ?? ?? 8b c8 8b d1 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 8b e5 5d c3 13 00 50 8f 05 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 89 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_MY_2147755596_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.MY!MTB"
        threat_id = "2147755596"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d9 8b 95 ?? ?? ?? ?? 0f be 02 2b c1 8b 8d ?? ?? ?? ?? 88 01 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d0 8b ca 8b c1 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 11 00 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_MZ_2147755598_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.MZ!MTB"
        threat_id = "2147755598"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 8b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 5d c3 06 00 33 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_MA_2147756733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.MA!MTB"
        threat_id = "2147756733"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 eb ?? 8b 15 ?? ?? ?? ?? 52 e8 ?? ?? ?? ?? 83 c4 04 e8 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? ?? 75 09 00 6a ?? 6a ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_MB_2147761849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.MB!MTB"
        threat_id = "2147761849"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 33 d9 8b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b db 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bunitu_MC_2147767055_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bunitu.MC!MTB"
        threat_id = "2147767055"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c6 2b c8 8b f1 c1 e6 ?? 03 75 ?? 8b c1 c1 e8 ?? 03 45 ?? 03 d9 33 f3 33 f0 c7 05 [0-8] 89 45 ?? 2b d6 8b 45 ?? 29 45 ?? 83 ef ?? 75 ?? 8b 45 ?? 5f 5e 89 10 89 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

