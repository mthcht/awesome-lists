rule Trojan_Win32_Tinba_A_2147657487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.A"
        threat_id = "2147657487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 c6 07 e9 2b c7 83 e8 05 89 47 01 eb 0e 68 00 80 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 76 20 03 75 08 8b 7d 08 03 3e 83 c6 04 ba 00 00 00 00 b8 07 00 00 00 f7 e2 8b d0 0f b6 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_F_2147695095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.F"
        threat_id = "2147695095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f3 a4 29 fe 80 7f fb e8 74 06 80 7f 75 03 01 77 fc 83 ee 05 c6 07 e9 89 77 01 8b 7d 0c 89 07 8b 7d ?? 8b 45 08 29 f8 83 e8 05 c6 07 e9 89 47 01 50 8d 45 ?? 87 04 24 ff 75 ?? 6a 20 ff 75 ?? ff 93}  //weight: 2, accuracy: Low
        $x_2_2 = {01 c1 01 c6 83 fe 05 72 ee 87 ce 89 f8 29 ce f3 a4 29 fe 83 ee 05 c6 07 e9 89 77 01 8b 7d 0c 89 07 8b 7d ?? 8b 45 08 29 f8 83 e8 05 c6 07 e9 89 47 01 8d 55 ?? 52 ff 75 ?? 6a 20 ff 75 ?? ff 93}  //weight: 2, accuracy: Low
        $x_2_3 = {03 52 3c 8b 52 78 01 c2 8b 72 20 01 c6 31 c9 41 83 c6 04 8b 3e 01 c7 81 7f 05 6f 63 41 64 75 ef}  //weight: 2, accuracy: High
        $x_2_4 = {00 4e 74 43 72 65 61 74 65 55 73 65 72 50 72 6f 63 65 73 73 00 ?? ?? ?? ?? ?? ?? ?? 00 4e 74 43 72 65 61 74 65 50 72 6f 63 65 73 73 45 78 00 ?? ?? ?? ?? ?? ?? ?? 00 4e 74 43 72 65 61 74 65 54 68 72 65 61 64 00 ?? ?? ?? ?? ?? ?? ?? 00 4e 74 52 65 73 75 6d 65 54 68 72 65 61 64 00 ?? ?? ?? ?? ?? ?? ?? 00 4e 74 45 6e 75 6d 65 72 61 74 65 56 61 6c 75 65 4b 65 79 00 ?? ?? ?? ?? ?? ?? ?? 00 4e 74 51 75 65 72 79 44 69 72 65 63 74 6f 72 79 46 69 6c 65 00 ?? ?? ?? ?? ?? ?? ?? 00 52 74 6c 43 72 65 61 74 65 55 73 65 72 54 68 72 65 61 64 00}  //weight: 2, accuracy: Low
        $x_1_5 = {87 04 24 6a 40 68 eb 00 00 00 ff b5 ?? ?? ?? ?? ff b5 ?? ?? ?? ?? ff 93}  //weight: 1, accuracy: Low
        $x_1_6 = {04 2f 0f 85 ?? ?? ?? ?? 6a 04 e8 0e 00 81 ?? 48 54 54 50 0f 85 ?? ?? ?? ?? 80}  //weight: 1, accuracy: Low
        $x_1_7 = {81 3e 47 45 54 20 74 17 81 3e 50 4f 53 54 0f 85 ?? ?? ?? ?? 80 7e 04 20 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tinba_I_2147725592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.I!bit"
        threat_id = "2147725592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 85 ad ff b3 e8 ?? ?? ?? 00 89 45 fc 8b 4d fc 68 ab 9b e1 ab 51 e8 ?? ?? ?? 00 83 c4 08 89 45 f8 6a 40 68 00 10 00 00 68 ?? ?? ?? 00 6a 00 ff 55 f8 89 45 fc 68 9c ea 25 e4 68 ?? ?? ?? 00 68 ?? ?? ?? 00 ff 75 fc e8 ?? ?? ?? 00 ff 55 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_DSK_2147740930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.DSK!MTB"
        threat_id = "2147740930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D7yHaaOgny2TMS" ascii //weight: 1
        $x_1_2 = "srBSLAGoFp" ascii //weight: 1
        $x_1_3 = "02E5YYKm" ascii //weight: 1
        $x_2_4 = {8b 85 50 ff ff ff 05 01 00 00 00 66 8b 4d de 66 81 f1 ea 06 66 89 4d de 89 85 50 ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tinba_GC_2147744031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.GC!MTB"
        threat_id = "2147744031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f af d1 88 95 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 0f be 85 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 88 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 2b 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 2b d1 89 95}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_RL_2147744032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.RL!MTB"
        threat_id = "2147744032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 0c 0a 89 45 ?? 89 4d ?? 8b 45 ?? 0f af 45 ?? 8b 4d ?? 8b 95 ?? ?? ?? ?? 89 8d ?? ?? ?? ?? 89 d1 8b b5 ?? ?? ?? ?? d3 ee 01 f0 8b 75 ?? 01 c6 66 8b 7d ?? 66 81 e7 ?? ?? 66 89 7d ?? 89 75 ?? 8d 45 ?? 66 8b 4d ?? 66 89 c2 66 09 d1 66 89 4d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_V_2147744060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.V!MTB"
        threat_id = "2147744060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 45 f5 24 ?? 88 45 f5 8b 4d f0 8b 55 f8 8a 45 e3 38 04 0a 74 ?? 8d 45 f5 8a 4d f7 88 c2 08 d1 88 4d f7 8b 45 f0 8a 4d f5 80 f1 ?? 88 4d f5 8b 75 dc 01 f0 89 45 f0 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 45 ec 0f b7 4d e2 8b 55 9c 01 ca 8b 4d a4 29 ca 66 89 d6 8b 55 d0 66 89 32 8b 55 ac 31 c2 89 55 ec 8a 5d b3 80 cb ?? 88 5d b3 8d 45 e8 66 8b 4d ba 66 89 c2 66 21 d1 66 89 4d ba b0 ?? b9 ?? ?? ?? ?? 8b 55 d0 81 c2 ?? ?? ?? ?? 8a 65 b3 2b 4d e8 89 55 d0 28 e0 88 45 b3 89 4d e8 e9}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 4d c8 8b 55 f0 21 c2 89 55 f0 c7 45 e8 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 4d c8 8d 45 e8 8b 4d cc 66 8b 55 be 66 81 c2 ?? ?? 8a 5d 9b 66 89 55 be 88 c7 08 fb 88 5d 9b 8b 85 ?? ?? ?? ?? 01 c1 89 4d cc e9}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 45 94 8b 4d ec 81 e1 ?? ?? ?? ?? 89 4d ec 3b 85 ?? ?? ?? ?? 74 ?? 8d 45 ec 8b 4d 90 89 ca 81 c2 ?? ?? ?? ?? c7 45 ec ?? ?? ?? ?? 89 55 90 8a 19 8b 4d 8c 89 ca 81 c2 ?? ?? ?? ?? 89 55 8c 88 19 8b 4d dc 31 c1 89 4d ec 8b 45 94 8b 8d ?? ?? ?? ?? 01 c8 8b 55 a4 81 c2 ?? ?? ?? ?? 89 45 94 89 55 a4 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tinba_PDSK_2147745484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.PDSK!MTB"
        threat_id = "2147745484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 39 47 3b fb 7c 0b 00 e8 ?? ?? ?? ?? 8b 8d ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {69 c0 fd 43 03 00 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 81 3d ?? ?? ?? ?? a5 02 00 00 8b 35 ?? ?? ?? ?? 75 05 00 a1}  //weight: 1, accuracy: Low
        $x_2_3 = {0f af df 03 c8 89 8d ?? ?? ff ff 8a 09 03 de 32 cb 88 8c 35 ?? ?? ff ff 0c 00 8b 8d ?? ?? ff ff 89 9d ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_4 = {8a 44 24 4b 04 f1 29 f9 88 84 24 8d 00 00 00 89 4c 24 58 8b 4c 24 74 8a 84 24 87 00 00 00 34 45 85 c9 8b 4c 24 58 8b 7c 24 3c 0f 44 f9 89 7c 24 7c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tinba_RX_2147747844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.RX!MTB"
        threat_id = "2147747844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 c2 05 09 0d ?? ?? ?? ?? 13 0d ?? ?? ?? ?? 81 35 ?? ?? ?? ?? d2 00 00 00 11 0d ?? ?? ?? ?? 83 25 ?? ?? ?? ?? 4f 89 06 89 0d ?? ?? ?? ?? 82 f1 74 83 e1 f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_MI_2147748451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.MI!MTB"
        threat_id = "2147748451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 81 f3 75 33 66 89 5c 24 6a 66 89 cb 66 09 df 66 89 7c 24 5e 66 89 c7 66 29 f7 66 89 bc 24 0a 02 00 00 8b 44 24 20 39 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_BJ_2147787668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.BJ!MTB"
        threat_id = "2147787668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REW is room acoustics analysis software for measuring" wide //weight: 1
        $x_1_2 = "TextConv.exe" wide //weight: 1
        $x_1_3 = "76749607097374937563457408670349764376" wide //weight: 1
        $x_1_4 = "6534896790767349067340673497697604767649760349" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_CC_2147811077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.CC!MTB"
        threat_id = "2147811077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 b0 03 55 a8 2b 55 b0 8b 45 b0 03 c2 89 45 b0 8b 4d 84 81 e9 f0 00 00 00 8b 55 84 2b d1 89 55 84 e9}  //weight: 1, accuracy: High
        $x_1_2 = {2b c8 89 4d c0 8b 55 84 03 55 90 8b 45 b0 8d 8c 10 bd 01 00 00 89 4d b0 8b 55 bc 2b 55 84 8b 45 90 2b c2 89 45 90 8b 4d bc 69 c9 4d fe ff ff 81 c1 e4 03 00 00 89 4d b0 c7 45 fc ff ff ff ff eb 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_BA_2147813296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.BA!MTB"
        threat_id = "2147813296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b d0 8a 4d e4 2a ca 88 4d e4 8b 55 d0 0f af 55 f4 8b 45 dc 03 c2 89 45}  //weight: 1, accuracy: High
        $x_1_2 = "kfRHgpGoTr" ascii //weight: 1
        $x_1_3 = "eNIAPFvDiD" ascii //weight: 1
        $x_1_4 = "EYULyNm" ascii //weight: 1
        $x_1_5 = "IwANei" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_GZN_2147814244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.GZN!MTB"
        threat_id = "2147814244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 1c 8b 0d ?? ?? ?? ?? 03 c0 2b 44 24 ?? 2b 44 24 ?? 03 c1 03 44 24 10 01 44 24 2c a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 7d 3b 8b 4c 24 10 41 0f af 4c 24 34 03 4c 24 3c c1 f8 ?? 51 8b 0d 0c 4f 43 00}  //weight: 10, accuracy: Low
        $x_1_2 = "GetSystemInfo" ascii //weight: 1
        $x_1_3 = "QueryPerformanceCounter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_MA_2147831536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.MA!MTB"
        threat_id = "2147831536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 85 60 ff ff ff 8d 4d a0 b2 00 8a b5 57 ff ff ff 80 f6 02 88 b5 57 ff ff ff 2a 95 4f ff ff ff 89 0c 24 89 44 24 04 8b 85 08 ff ff ff 89 44 24 08 88 95 f7 fe ff ff e8 3c bd ff ff 8b 4d 88 8a 95 57 ff ff ff 80 ca 6e 8a b5 f7 fe ff ff 88 b5 4f ff ff ff 88 95 57 ff ff ff 8b b5 1c ff ff ff 39 f1 89 85 f0 fe ff ff 0f 85}  //weight: 10, accuracy: High
        $x_1_2 = "CreateMailslotWGetTickCoum" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_MA_2147831536_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.MA!MTB"
        threat_id = "2147831536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 34 03 44 24 24 8b 4c 24 14 8a 04 10 8b 54 24 24 2b cf 88 04 11 ff 44 24 24 8b 44 24 24 3b 44 24 4c 0f 8c}  //weight: 1, accuracy: High
        $x_1_2 = "Detected memory leaks!" ascii //weight: 1
        $x_1_3 = "PostQuitMessage" ascii //weight: 1
        $x_1_4 = "CreateStdAccessibleProxyA" ascii //weight: 1
        $x_1_5 = "IsProcessorFeaturePresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_ATB_2147843595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.ATB!MTB"
        threat_id = "2147843595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 03 03 c7 45 ec b4 98 4b c0 02 02 03 03 02 03 03 02 02 03 03 02 02 03 c7 45 ec ?? ?? ?? ?? 03 02 ff 75 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_RF_2147895082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.RF!MTB"
        threat_id = "2147895082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b ca 69 d2 ab 98 00 00 8b f0 2b f2 2b c8 8b d0 2b d6 83 e9 11 8d 8c 11 7f be 00 00 89 35}  //weight: 5, accuracy: High
        $x_1_2 = "nosnledomtrtgbominmaFheetISmtBe.a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_AMMC_2147905124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.AMMC!MTB"
        threat_id = "2147905124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 ce 30 f2 88 55 c7 8b 4d d4 8b 75 b0 29 f0}  //weight: 2, accuracy: High
        $x_2_2 = {88 1a 8b 55 d4 8b 75 c0 8b 7d c0 31 cf 89 7d c0 21 c6 89 75 c0 8b 45 ac 01 c2 89 55 d4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_MBZW_2147907375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.MBZW!MTB"
        threat_id = "2147907375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c4 28 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 e0 25 40 00 80 24 40 00 cc 14 40 00 78 00 00 00 82 00 00 00 8c}  //weight: 1, accuracy: High
        $x_1_2 = {4f 6c 79 6d 70 69 63 53 74 00 44 65 61 6c 61 68 6f 79 61 00 00 44 65 61 6c 61 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_AMMF_2147908982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.AMMF!MTB"
        threat_id = "2147908982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mKoSQnHypCM" ascii //weight: 1
        $x_1_2 = "NIJMxqxcCo" ascii //weight: 1
        $x_1_3 = "OrKqNggrlDmJt" ascii //weight: 1
        $x_1_4 = "D:\\Maz-milocevic4\\FlashGames.vbp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_MKV_2147920564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.MKV!MTB"
        threat_id = "2147920564"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b c8 03 4d dc 8b 55 f0 03 d1 89 55 f0 8b 45 d8 0f af 45 b4 03 45 cc 8a 4d d0 02 c8 88 4d d0 8b 55 b8 83 c2 02 89 55 b8 8b 45 b8 33 c9 66 8b 08 85 c9 0f 85 f0 fe ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_MKA_2147929788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.MKA!MTB"
        threat_id = "2147929788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4a 0c 8b 95 ?? ?? ff ff 8a 0c 11 8b 95 ?? ?? ff ff 32 0c 10 8b 95 a8 fe ff ff 88 0c 10 ff d7 8b d0 8d 8d ?? ?? ff ff ff d6 50 6a 6b ff d7 8b d0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_2147931799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.MTV!MTB"
        threat_id = "2147931799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTV: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 11 88 55 d6 8b 4d f0 03 4d be 89 4d f0 8b 4d f4 03 4d be 89 4d f4 0f b6 4d d6 0f b6 55 d7 c7 45 ?? fb 9e f1 81 33 ca 8b 45 c6 88 08 c7 45 ?? 19 d9 b2 12 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_RLA_2147937534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.RLA!MTB"
        threat_id = "2147937534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 4d e8 8a 75 cb 80 c6 4f 88 75 cb 88 10 8b 45 d8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_RLB_2147939893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.RLB!MTB"
        threat_id = "2147939893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 4c 24 38 32 4c 24 5b 88 4c 24 4f 8a 4c 24 4f 6a 05 56 88 4c 04 2c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_CCJX_2147940071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.CCJX!MTB"
        threat_id = "2147940071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 ac c1 e2 ed 33 55 a4 89 55 cc c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b 4d b8 03 4d c8 8b 75 d8 d3 e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_EDG_2147940174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.EDG!MTB"
        threat_id = "2147940174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 c0 2b 44 24 10 03 c1 89 44 24 24 8b 44 24 40 0f af 44 24 2c 8d 44 10 0a 89 44 24 14 a1 ?? ?? ?? ?? 3b 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_ATI_2147940999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.ATI!MTB"
        threat_id = "2147940999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 d2 f7 f1 89 45 c4 8b 55 a8 81 e2 b9 02 00 00 8b 45 c8 2b c2 89 45 c8 c7 85 a8 fe ff ff e8 c5 41 00 8b 8d a8 fe ff ff 51 68 98 0f 00 00 68 78 0a 00 00 ff 15 ?? ?? ?? ?? 8b 75 b4 03 75 c8 8b 4d d8 d3 e6}  //weight: 3, accuracy: Low
        $x_2_2 = {8b 45 c4 33 d2 f7 f6 89 45 c4 ba 71 02 00 00 2b 55 d8 8b 45 c4 33 c2 89 45 c4 68 79 01 00 00 8d 8d 98 fe ff ff 51 ff 15 ?? ?? ?? ?? 8b 55 c0 8b 4d dc d3 e2 8b 4d d8 d3 e2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tinba_AHB_2147947302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinba.AHB!MTB"
        threat_id = "2147947302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 85 6c ff ff ff 8b 55 dc c1 f8 1f 8b c8 33 ca 8b 55 d8 33 c2 3b c1 0f}  //weight: 3, accuracy: High
        $x_2_2 = {89 85 38 fe ff ff 89 85 34 fe ff ff 89 85 30 fe ff ff 89 85 2c fe ff ff 89 85 28 fe ff ff 89 85 18 fe ff ff 89 85 08 fe ff ff ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

