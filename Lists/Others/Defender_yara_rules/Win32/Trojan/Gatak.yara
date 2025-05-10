rule Trojan_Win32_Gatak_A_2147686279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.gen!A"
        threat_id = "2147686279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "veverka.junyks.cz/report2_" ascii //weight: 1
        $x_1_2 = "veverka.junyks.cz/report1_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gatak_DT_2147690901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.DT!dha"
        threat_id = "2147690901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c6 45 f8 00 c6 45 d8 4d c6 45 d9 70 c6 45 da 53 c6 45 db 74 c6 45 dc 61 c6 45 dd 72 c6 45 de 74 c6 45 df 50 c6 45 e0 72 c6 45 e1 6f c6 45 e2 63 c6 45 e3 65 c6 45 e4 73 c6 45 e5 73 c6 45 e6 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gatak_DT_2147690901_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.DT!dha"
        threat_id = "2147690901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c7 89 7d ?? 29 f1 8b 45 ?? 8a 5d ?? 80 cb ?? 88 5d ?? 89 4d ?? 8a 5d ?? 38 1c 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gatak_DT_2147690901_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.DT!dha"
        threat_id = "2147690901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c6 45 f0 31 c6 45 f1 32 c6 45 f2 33 c6 45 f3 34 c6 45 f4 35 c6 45 f5 35 c6 45 f6 34 c6 45 f7 33 c6 45 f8 32 c6 45 f9 31 88 5d fa ff 15 ?? ?? ?? ?? 66 85 c0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gatak_DT_2147690901_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.DT!dha"
        threat_id = "2147690901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CMD /C SYSTEMINFO && SYSTEMINFO && SYSTEMINFO && SYSTEMINFO && SYSTEMINFO && DEL" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gatak_DR_2147694666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.DR!!Gatak.gen!A"
        threat_id = "2147694666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "Gatak: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 ec 6e c6 45 ed 74 c6 45 ee 64 c6 45 ef 6c c6 45 f0 6c c6 45 f1 2e c6 45 f2 64 c6 45 f3 6c c6 45 f4 6c}  //weight: 1, accuracy: High
        $x_1_2 = {74 06 81 f6 20 83 b8 ed d1 ea 4f 75 eb}  //weight: 1, accuracy: High
        $x_1_3 = {77 03 80 c2 20 38 54 35 ec 75 0f 46 41 41 83 fe 09 72 e3}  //weight: 1, accuracy: High
        $x_1_4 = {68 eb 2f 76 e0 e8 ?? ?? ff ff 68 5e ce d6 e9 89 45 e8 e8 28 fb ff ff 68 f2 79 36 18 89 45 ec e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = {e8 15 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e}  //weight: 1, accuracy: High
        $x_1_6 = {e8 11 00 00 00 77 77 77 2e 67 6f 6f 67 6c 65 2e}  //weight: 1, accuracy: High
        $x_1_7 = {e8 47 00 00 00 68 74 74 70 3a 2f 2f 68 6f 73 74 74 68 65 6e 70 6f 73 74 2e 6f 72 67 2f 75 70 6c 6f 61 64 73 2f}  //weight: 1, accuracy: High
        $x_1_8 = "/report_N_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Gatak_DR_2147694666_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.DR!!Gatak.gen!A"
        threat_id = "2147694666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "Gatak: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 62 5f c6 45 63 73 c6 45 64 74 c6 45 65 61 c6 45 66 72 c6 45 67 74 c6 45 68 5f c6 45 69 25 c6 45 6a 64 c6 45 6b 5f c6 45 6c 25 c6 45 6d 64}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 66 5f c6 45 67 65 c6 45 68 72 c6 45 69 72 c6 45 6a 32 c6 45 6b 5f c6 45 6c 5f c6 45 6d 25 c6 45 6e 64}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 5e 5f c6 45 5f 66 c6 45 60 69 c6 45 61 6e c6 45 62 69 c6 45 63 73 c6 45 64 68 c6 45 65 5f c6 45 66 25 c6 45 67 64 c6 45 68 5f c6 45 69 25 c6 45 6a 64 c6 45 6b 5f c6 45 6c 5f c6 45 6d 25 c6 45 6e 64}  //weight: 1, accuracy: High
        $x_1_4 = {8b 75 10 80 3e 89 59 59 0f 85 ?? ?? ?? ?? 80 7e 01 50 0f 85 ?? ?? ?? ?? 80 7e 02 4e 0f 85 ?? ?? ?? ?? 80 7e 03 47 0f 85}  //weight: 1, accuracy: Low
        $x_1_5 = {38 5d f9 74 0a c6 45 fc 36 c6 45 fd 34 eb 08 c6 45 fc 33 c6 45 fd 32}  //weight: 1, accuracy: High
        $x_1_6 = {72 e0 8b 46 04 c6 00 7e 8d 45 e8 50 c6 45 e8 2e c6 45 e9 74 c6 45 ea 6d c6 45 eb 70 c6 45 ec 00}  //weight: 1, accuracy: High
        $x_1_7 = {c6 45 fc 7e c6 45 fd 58 c6 45 fe 58 88 5d ff ff 15}  //weight: 1, accuracy: High
        $x_1_8 = {8b c6 99 f7 7d 10 8b 45 0c 8a 04 02 02 04 0e 8a 14 0e 00 45 0b 0f b6 45 0b 03 c1 8a 18 88 1c 0e 46 3b f7 88 10 7c d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Gatak_DR_2147695764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.DR!dha"
        threat_id = "2147695764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {c6 45 ec 6e c6 45 ed 74 c6 45 ee 64 c6 45 ef 6c c6 45 f0 6c c6 45 f1 2e c6 45 f2 64 c6 45 f3 6c c6 45 f4 6c}  //weight: 4, accuracy: High
        $x_4_2 = {33 f6 8a 11 8a da 80 eb 41 80 fb 19 77 03 80 c2 20 38 54 35 ec 75 0f}  //weight: 4, accuracy: High
        $x_1_3 = {6a 40 83 c6 04 8b 04 3e 68 00 30 00 00 89 45 f8 8d 45 f8 50 6a 00 8d 45 fc 50 6a ff 83 c6 04 89 5d fc}  //weight: 1, accuracy: High
        $x_4_4 = "veverka.junyks.cz/report" ascii //weight: 4
        $x_1_5 = "uploads/ec8724312886c68b2c2e5c46d0a36c47.png" ascii //weight: 1
        $x_1_6 = "imagesup.net/?di=12140432977611" ascii //weight: 1
        $x_1_7 = "3cb5c8fbf016f6fc7b69a17acd3bda1f.png" ascii //weight: 1
        $x_1_8 = "gesup.net/?di=214046519679" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Gatak_DP_2147695766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.DP!dha"
        threat_id = "2147695766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 87 ea 00 10 e9 91 04 00 00}  //weight: 1, accuracy: High
        $x_10_2 = {73 12 8b 45 08 03 45 f8 8b 4d 0c 03 4d f8 8a 09 88 08 eb df c6 45 ff 01 8a 45 ff c9 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gatak_DU_2147695773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.DU!dha"
        threat_id = "2147695773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b f8 68 eb 2f 76 e0 e8 ?? ?? ?? ?? 68 5e ce d6 e9 89 45 ?? e8 ?? ?? ?? ?? 68 f2 79 36 18 89 45 ?? e8 ?? ?? ?? ?? 8b 7d ?? 33 f6 89 45 ?? 8a 07 83 c4 0c 46 3c 43}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gatak_EA_2147695774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.EA!dha"
        threat_id = "2147695774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "EV_MMAC_OID_DOT11_PRISE_VERS_ASSWORD" ascii //weight: 100
        $x_1_2 = "WdfFdoQueryShutdown" ascii //weight: 1
        $x_1_3 = "EV_MMAC_RF_KILL_WAIT3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Gatak_DV_2147695783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.DV!dha"
        threat_id = "2147695783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 f8 c1 e8 10 0f b6 c0 3b c6 7c 01 47 8b 45 f8 c1 e8 08 0f b6 c0 3b c6 7c 01 47}  //weight: 5, accuracy: High
        $x_5_2 = {80 3e 89 59 59 0f 85 ?? ?? ?? ?? 80 7e 01 50 0f 85 ?? ?? ?? ?? 80 7e 02 4e 0f 85 ?? ?? ?? ?? 80 7e 03 47}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gatak_DQ_2147695795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.DQ!dha"
        threat_id = "2147695795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 41 54 51 00 68 43 4c 42 43 54 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {31 c0 50 68 41 54 51 00 68 43 4c 42 43 54 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 68 41 54 51 00 68 43 4c 42 43 54 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Gatak_DW_2147695796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.DW!dha"
        threat_id = "2147695796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "INTKL_NDT_STATUS_PWD_TGT_RUNNINSUFFLRWN" ascii //weight: 1
        $x_1_2 = "UL_UNRKACONNCL_SXAKUS_GOD_DFLYSY" ascii //weight: 1
        $x_1_3 = "STATNS_YTO32.dll" ascii //weight: 1
        $x_1_4 = "TAS_CLSSE_NUT_3" ascii //weight: 1
        $x_2_5 = "AMT_SERVER_DET" ascii //weight: 2
        $x_2_6 = "ModultsNound" ascii //weight: 2
        $x_4_7 = "mcciwh.sysdir" ascii //weight: 4
        $x_2_8 = "mcctcm.sysysr" ascii //weight: 2
        $x_2_9 = "Rx: Dhffer Dasa" ascii //weight: 2
        $x_2_10 = "Microsoft\\SHVU\\jltle" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gatak_DX_2147695797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.DX!dha"
        threat_id = "2147695797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {64 a1 30 00 00 00 89 45 fc 8b 45 fc 8b 40 0c 8b 40 0c 53 c6 45 ec 6e c6 45 ed 74 c6 45 ee 64 c6 45 ef 6c c6 45 f0 6c c6 45 f1 2e c6 45 f2 64 c6 45 f3 6c c6 45 f4 6c c6 45 f5 00 56 66 83 78 2c 12 75 ?? 8b 48 30 33 f6 8a 11 8a da 80 eb 41 80 fb 19 77 ?? 80 c2 20 38 54 35 ec 75 ?? 46 41 41 83 fe 09 72 ?? 8b 40 18}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gatak_DEA_2147756358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.DEA!MTB"
        threat_id = "2147756358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d8 8b 4d dc 0f b6 04 01 8b 4d d8 83 e1 03 83 c1 02 0f b6 4c 0d f1 29 c8 88 c2 8b 45 e8 03 45 ec 8b 4d d8 88 14 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gatak_BH_2147941067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatak.BH!MTB"
        threat_id = "2147941067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 ef 8d 6e 40 55 56 e8 ?? ?? 00 00 83 c4 08 31 c0 0f 1f 44 00 00 0f b6 4c 05 00 30 0c 07 40 39 d8 72}  //weight: 2, accuracy: Low
        $x_2_2 = {31 c9 c7 44 24 68 74 65 20 6b c7 44 24 60 32 2d 62 79 c7 84 24 ec 00 00 00 6e 64 20 33}  //weight: 2, accuracy: High
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

