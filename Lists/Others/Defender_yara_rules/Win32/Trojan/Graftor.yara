rule Trojan_Win32_Graftor_DSK_2147742181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.DSK!MTB"
        threat_id = "2147742181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a d3 80 e2 f0 8a c3 02 d2 24 fc 02 d2 08 54 24 12 c0 e0 04 08 44 24 11 81 3d a4 bf 46 00 c5 02 00 00 c7 05 a8 1c 44 00 50 d5 10 a8}  //weight: 2, accuracy: High
        $x_2_2 = {8a 54 24 12 8a 44 24 11 88 14 2e 80 e3 c0 08 5c 24 13 88 44 2e 01 81 3d a4 bf 46 00 08 07 00 00 c7 05 98 bf 46 00 d6 26 f2 ce c7 05 9c bf 46 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_SIBC_2147806067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.SIBC!MTB"
        threat_id = "2147806067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "ServiceDll" ascii //weight: 10
        $x_1_2 = {33 ff 5b 8a 46 ?? 8a 0e d0 e0 02 46 ?? 6a 04 d0 e1 02 4e ?? d0 e0 02 46 ?? 0f be c9 d0 e0 02 46 ?? 03 cf c1 e1 ?? 0f be c0 8d 84 08 ?? ?? ?? ?? 8b 4d ?? 50 ff 75 ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 c7 ?? 83 c6 ?? 4b 75}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c0 39 44 24 0c 7e ?? 56 8b 74 24 0c 8b d0 c1 fa ?? 8a c8 8a 14 32 80 e1 ?? d2 fa 8b 4c 24 08 80 e2 ?? 88 14 08 40 3b 44 24 10 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_CA_2147814338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.CA!MTB"
        threat_id = "2147814338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 33 88 04 3e 83 fe ?? 75 12 8d 4d ?? 51 6a 40 68 [0-4] 57 ff 15 [0-4] 46 3b 75 fc 72 d5}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 00 ff 15 [0-4] 81 ff c0 c6 2d 00 76 1a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_CB_2147814342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.CB!MTB"
        threat_id = "2147814342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f2 46 8a 02 32 42 01 0f b6 c0}  //weight: 1, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_ABS_2147851291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.ABS!MTB"
        threat_id = "2147851291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spy: I download file new copy, now i start it" wide //weight: 1
        $x_1_2 = "Main: Spy started, all ok" wide //weight: 1
        $x_1_3 = "GET /spm.php?sendlog=" ascii //weight: 1
        $x_1_4 = "Host: 83.149.95.197:80" ascii //weight: 1
        $x_1_5 = "ftp://" ascii //weight: 1
        $x_1_6 = "software\\microsoft\\windows nt\\currentversion\\winlogon" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_GNZ_2147852911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.GNZ!MTB"
        threat_id = "2147852911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {a0 34 48 bc 37 35 fd dd b4 95 5b 05 01 f0 9c b2 0c 06 a2 f0 6d 40 d7 51}  //weight: 10, accuracy: High
        $x_1_2 = "w9$cfE4" ascii //weight: 1
        $x_1_3 = "@DnCWkjz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_GMH_2147889534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.GMH!MTB"
        threat_id = "2147889534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 83 c4 14 48 89 35 ?? f6 60 00 5f 5e}  //weight: 10, accuracy: Low
        $x_10_2 = {56 53 ff 15 ?? ?? ?? ?? a1 ?? 49 61 00 89 35 ?? f7 60 00 8b fe 38 18}  //weight: 10, accuracy: Low
        $x_1_3 = "hlaZdcibz" ascii //weight: 1
        $x_1_4 = "VMProtect end" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_SPDX_2147897798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.SPDX!MTB"
        threat_id = "2147897798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {b9 14 8a 43 00 81 c3 70 22 0c ee 81 c3 67 26 6c 9d bb 57 37 53 02 e8 ?? ?? ?? ?? bb c4 5e 62 4a 29 fb 47 31 0e bb 5d 00 45 9e 81 c6 01 00 00 00 68 56 82 44 79 8b 3c 24 83 c4 04 4b 57 5b 39 d6 75 be}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_AMBG_2147899777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.AMBG!MTB"
        threat_id = "2147899777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c1 33 d2 f7 f7 8a 44 14 ?? 30 04 31 41 a1 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 2b c6 3b c8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_A_2147903172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.A!MTB"
        threat_id = "2147903172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 f7 da 1b d2 f7 da}  //weight: 2, accuracy: High
        $x_2_2 = {8b c8 8b 45 ?? 99 f7 f9 8d}  //weight: 2, accuracy: Low
        $x_2_3 = {0f bf c0 33 d8 8d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_B_2147903174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.B!MTB"
        threat_id = "2147903174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Enabled:Windows Messanger\" /f" wide //weight: 2
        $x_2_2 = "cmd.exe /c netsh firewall set opmode disable" wide //weight: 2
        $x_2_3 = "cmd.exe /c net stop security center" wide //weight: 2
        $x_2_4 = "cmd.exe /c net stop WinDefend" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_GPA_2147904589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.GPA!MTB"
        threat_id = "2147904589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 1c ec 24 6a 01 ff 15 48 20 40 c0 85 c0 0f 7c 76 8d 44 fc 0e 50 68 38 1d 6a 04 de 30 5b 58 13}  //weight: 1, accuracy: High
        $x_1_2 = {28 38 10 68 10 30 c6 0a 66 c7 34 38 1c 03 6e 0d ee 01 1c 32 5d 3c 2c 4d 08 31 8b f0 69 04 51 9e}  //weight: 1, accuracy: High
        $x_1_3 = {50 40 4d 5e 0e fa 20 33 c0 83 c4 14 24 c3 90 01 00 55 8b ec 6a ff 68 78 a0 5e d0 11 80 64 a1 d0}  //weight: 1, accuracy: High
        $x_1_4 = {e8 79 a8 fc a1 64 01 7a 0c 4f 59 a5 0d 80 5f 88 72 0e 84 13 22 2a 10 7d 8b 63 7c 1b 89 08 21 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_HNA_2147907540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.HNA!MTB"
        threat_id = "2147907540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {4e 0e 71 b5 bf 97 33 e1 3a de 7b 6a 19 80 2d 74 19 c9 f6 c2 83 8d 4c 49 0b e9 ?? ?? ?? ?? 53 48 45 4c 4c 33 32 2e 44 4c 4c 00 d2 c0 18 e0 b0 2e 68 51 89 e9 36 f9 f8 e9 f8 28 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_ARA_2147913513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.ARA!MTB"
        threat_id = "2147913513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 5c 04 10 80 f3 1a 88 5c 04 10 40 83 f8 05 72 ef}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_ARA_2147913513_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.ARA!MTB"
        threat_id = "2147913513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 10 8a 14 1a 8b 4d 10 30 14 31 ff 00 39 38 75 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_C_2147921682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.C!MTB"
        threat_id = "2147921682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 d2 d3 f1 c0 c1 ?? 33 da 03 ea 0a c9 8b 84 31 ?? ?? ?? ?? 8d b4 0e ?? ?? ?? ?? c1 e9 ?? 0f b7 d1 87 4c ?? ?? 33 c3 d3 f2 0f 99 c2 0f c8 40 35 ?? ?? ?? ?? 66 03 ca c1 c8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_MKV_2147924864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.MKV!MTB"
        threat_id = "2147924864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 ca 0f b6 c9 02 c1 0f b6 c0 8d 44 83 04 8a 08 30 0f 8b 08 8b 85 ?? ?? ?? ?? 31 08 8b 0e 03 8d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 31 08 ff 85 ?? ?? fe ff 81 bd ?? ?? fe ff 38 3d 49 00 0f 8c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_NG_2147925324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.NG!MTB"
        threat_id = "2147925324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 55 ec b8 14 5c 41 00 e8 ?? ?? ff ff 8d 45 e8 e8 ?? ?? ff ff 8b 55 e8 a1 14 5c 41 00 e8 ?? ?? ff ff 75 7b e8 ?? ?? ff ff 84 c0 74 61 8d 45 e4 50 8d 55 e0}  //weight: 3, accuracy: Low
        $x_2_2 = {8d 55 c4 33 c0 e8 ?? ?? fe ff 8b 45 c4 b9 03 00 00 00 ba 01 00 00 00 e8 ?? ?? ff ff 8b 55 c8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_AWFA_2147928080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.AWFA!MTB"
        threat_id = "2147928080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {46 81 e6 ff 00 00 00 8a 44 34 ?? 8a d8 03 df 81 e3 ff 00 00 00 8b fb 8a 5c 3c ?? 88 5c 34 ?? 88 44 3c ?? 8a 5c 34 ?? 03 d8 81 e3 ff 00 00 00 8a 44 1c ?? 8a 1c 29 32 c3 88 01 41 4a 75}  //weight: 5, accuracy: Low
        $x_1_2 = "stttdelzzz.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_BA_2147931027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.BA!MTB"
        threat_id = "2147931027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {83 c4 04 8b 45 f8 33 d2 b9 0e 00 00 00 f7 f1 8b 45 f4 0f b6 0c 10 8b 55 f8 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d f8 88 81}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_BAA_2147932665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.BAA!MTB"
        threat_id = "2147932665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 55 e4 8b 45 e4 8d 8c 10 54 1e 00 00 03 4d e4 89 4d e4 8b 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_PG_2147936653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.PG!MTB"
        threat_id = "2147936653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d6 8b c8 33 d2 8b c3 f7 f1 8b 45 ?? 8b 4d ?? 03 c3 43 8a 92 ?? ?? ?? ?? 32 14 01 88 10 83 fb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_BAB_2147936774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.BAB!MTB"
        threat_id = "2147936774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f6 d2 02 d0 80 f2 01 d0 c2 f6 d2 80 c2 7f 88 90 ?? ?? ?? ?? 40 3d 05 4e 00 00 72 de}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_BAC_2147937531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.BAC!MTB"
        threat_id = "2147937531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f6 d1 80 c1 42 80 f1 a3 80 c1 4b 80 f1 e7 88 8c 1d ?? ?? ?? ?? 83 c3 01 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_SEFT_2147938420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.SEFT!MTB"
        threat_id = "2147938420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "titisimiumislima" wide //weight: 2
        $x_2_2 = "josplovismiuzilama" wide //weight: 2
        $x_2_3 = "dazaboravimnasve" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Graftor_SX_2147947158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Graftor.SX!MTB"
        threat_id = "2147947158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff 36 8d 85 f8 fe ff ff 50 ff 15 ?? ?? ?? ?? 59 85 c0 59 74 1b 47 83 c6 04 3b 7d 0c 7c e2}  //weight: 3, accuracy: Low
        $x_2_2 = {b9 81 00 00 00 33 c0 8d bd ee fa ff ff f3 ab 80 a5 f8 fd ff ff 00 6a 40 66 ab 59 33 c0 8d bd f9 fd ff ff 68 e0 40 40 00 f3 ab 66 ab aa}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

