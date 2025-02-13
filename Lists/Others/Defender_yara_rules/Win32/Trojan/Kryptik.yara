rule Trojan_Win32_Kryptik_A_2147739718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.A!MTB"
        threat_id = "2147739718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 00 00 00 00 f7 75 e4 89 d1 89 ca 8b 45 08 01 d0 8a 00 31 f0 88 03 ff 45 f4 8b 45 f4 3b 45 10 0f 95 c0 84 c0}  //weight: 1, accuracy: High
        $x_1_2 = "2ucp7Xrh0EK19E4" ascii //weight: 1
        $x_1_3 = "5w5EzPC0C10QrKw(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_BS_2147740668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.BS!MTB"
        threat_id = "2147740668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e4 e7 ad 7a c7 44 24 ?? e5 2e cd 5b c7 44 24 ?? 9a dc a0 75 81 6c 24 ?? ad 7d d8 77 81 44 24 ?? eb 57 f8 5e 81 44 24 ?? 0e 1a 61 2a 81 44 24 ?? b4 c8 b9 65 81 44 24 ?? 0a 73 d7 07 81 44 24 ?? ca bb e3 2a a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 3e 46 3b f3 7c f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_BM_2147740843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.BM!MTB"
        threat_id = "2147740843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 74 38 03 88 b5 fb ?? ?? ?? 8a d6 8a 8d fb ?? ?? ?? 80 e2 f0 80 e6 fc c0 e1 06 0a 4c 38 02 c0 e2 02 0a 14 38 c0 e6 04 0a 74 38 01 81 3d ?? ?? ?? ?? be 00 00 00 88 8d fb ?? ?? ?? 8b 8d ec ?? ?? ?? 88 95 fa ?? ?? ?? 88 b5 f9 ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_BN_2147740844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.BN!MTB"
        threat_id = "2147740844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 20 00 00 00 00 81 6c 24 20 aa a0 5b 7e 81 44 24 20 62 7e e6 6f 81 44 24 20 4d 22 75 0e 8b 4c 24 20 8b d0 d3 ea 03 c7 03 54 24 40 33 d0 33 d6 2b ea 81 3d ?? ?? ?? ?? fd 13 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_BO_2147741019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.BO!MTB"
        threat_id = "2147741019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a cb 8a 6d fd 80 f1 dd 8a 5d fe 8a 55 ff 32 6d f5 32 5d f6 32 55 f7 88 4d fc 88 6d fd 88 5d fe 88 55 ff 80 f9 e9 75}  //weight: 1, accuracy: High
        $x_1_2 = {83 e0 03 0f b6 44 05 f4 30 82 ?? ?? ?? ?? 8b c6 83 e0 03 83 c6 05 0f b6 44 05 f4 30 82 ?? ?? ?? ?? 83 c2 05 81 fa 05 5a 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_S_2147741122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.S!MTB"
        threat_id = "2147741122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d9 8a f9 80 e3 ?? c0 e1 ?? 0a 4c 28 ?? 80 e7 ?? c0 e3 ?? 0a 1c 28 c0 e7 ?? 0a 7c 28}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d3 d3 ea 8b 4c 24 ?? 03 54 24 ?? 8d 04 19 33 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_DR_2147741630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.DR!MTB"
        threat_id = "2147741630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {bb a0 9a c0 5c 81 45 ?? 5c 28 e5 31 81 6d ?? dc 13 2c 04 c1 eb 02 81 45 ?? dc 13 2c 04 25 5b 9e bb 32 81 6d ?? ba f6 28 52 81 e3 21 4b 69 37 81 45 ?? 7a 84 d5 38 81 6d ?? fc 12 12 48 81 45 ?? 3c 85 65 61 81 e3 81 a1 03 37 81 6d ?? 64 d7 c4 16 c1 eb 1f 81 6d ?? ba b9 4f 2c 81 45 ?? 1e 91 14 43 81 45 ?? c0 00 00 00 8a 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_G_2147742244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.G!MTB"
        threat_id = "2147742244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 0c 10 8b 0d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? ?? ?? ?? ?? ?? 0f 44 c7 42 a3 ?? ?? ?? ?? 3b d1 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 54 19 02 8a 4c 19 03 88 8d ?? ?? ?? ?? 80 e1 ?? c0 e1 ?? 88 95 ?? ?? ?? ?? 88 8d ?? ?? ?? ?? 83 f8 ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8a c1 8a b5 ?? ?? ?? ?? 24 ?? c0 e0 ?? c0 e1 ?? 0a d0 08 8d ?? ?? ?? ?? 88 34 3e 81 3d [0-8] 88 95 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_4 = {8b c7 c1 e8 ?? 03 85 ?? ?? ?? ?? 33 [0-5] 33 ?? 2b f0 83 [0-6] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_GM_2147742414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.GM!MTB"
        threat_id = "2147742414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 3b 05 ?? ?? ?? ?? 72 ?? eb ?? 8b 4d fc 89 4d f4 8b 15 ?? ?? ?? ?? 03 55 fc 89 15 ?? ?? ?? ?? 8b 45 f4 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 ?? 8b 4d f0 8b 55 fc 8d 84 0a ?? ?? ?? ?? 89 45 ec 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 55 fc 83 c2 ?? 89 55 fc 8b 45 ec a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 85 c9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_GG_2147742426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.GG!MTB"
        threat_id = "2147742426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 88 10 c7 45 ?? ?? ?? ?? ?? 8b 45 f8 83 c0 01 89 45 f8 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c0 8b ca 8b c0 8b d0 33 d1 8b c2 c7 05 [0-8] 01 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_GN_2147742427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.GN!MTB"
        threat_id = "2147742427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 88 10 c7 45 ?? ?? ?? ?? ?? 8b 45 f8 83 c0 01 89 45 f8 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c0 8b ca 8b c0 [0-13] 33 [0-14] c7 05 [0-8] 01 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 [0-1] 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_GS_2147742535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.GS!MTB"
        threat_id = "2147742535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 9b cf a0 f7 8b f8 eb 12 81 fe 53 09 00 00 76 0a 8b c7 2b f7 33 d2 f7 f1 8b fa 33 db 83 fe 35}  //weight: 1, accuracy: High
        $x_1_2 = {8b de 0f af d8 81 c6 9b 8f 4e 72 89 75 fc 89 5d 08 33 ff 47 b9 9b cf a0 f7 83 fb 41 76 66 85 f6 8b cf 8b c3 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_GA_2147742542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.GA!MTB"
        threat_id = "2147742542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 44 24 28 8b 13 8a 44 24 28 8b f1 33 ed 03 f2 8a 16 3a d0 75 1f 8b c7 8b fe 2b 7c 24 2c 84 d2 74 0f 80 38 00 74}  //weight: 1, accuracy: High
        $x_1_2 = {8b 75 d8 81 fe 00 00 00 01 77 9b c7 05 ?? ?? ?? ?? 50 72 6f 63 c7 05 ?? ?? ?? ?? 65 73 73 33 c7 05 ?? ?? ?? ?? 32 46 69 72 66 c7 05 ?? ?? ?? ?? 73 74 68 ?? ?? ?? ?? 56 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_GA_2147742542_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.GA!MTB"
        threat_id = "2147742542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 30 a1 ?? ?? ?? ?? 88 0c 30 a1 ?? ?? ?? ?? 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 54 19 02 8a 4c 19 03 88 8d ?? ?? ?? ?? 80 e1 ?? c0 e1 ?? 88 95 ?? ?? ?? ?? 88 8d ?? ?? ?? ?? 83 f8 ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {24 fc c0 e0 ?? c0 e1 ?? 0a d0 08 8d ?? ?? ?? ?? 88 34 3e 81 3d [0-8] 88 95 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_4 = {8b c7 c1 e8 ?? 03 85 ?? ?? ?? ?? 33 c3 33 c2 2b f0 83 [0-6] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Kryptik_AR_2147742680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.AR!MTB"
        threat_id = "2147742680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tonacexigoyase jelodiwa bevucerolavo sanoxowe wari" ascii //weight: 1
        $x_1_2 = "jadamapukoxoluhehovewica nekodapecoruwebigu yajurapu mevu zita cucifetatiyuxu duvema catehoguburoxiherayo badamatoxuninuwisuxugayuso" ascii //weight: 1
        $x_1_3 = "Zifokohinecebu ludifefimucaseye xawiciwo wagevu xokisoci davoxuyuhabu capopumorukecucu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_RA_2147744725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.RA!MTB"
        threat_id = "2147744725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c8 8b 55 ?? 03 55 ?? 0f be 02 33 c1 8b 4d ?? 03 4d ?? 88 01 8b 55 ?? 83 ea 01 89 55 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_P_2147745862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.P!MTB"
        threat_id = "2147745862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HutVabBin" wide //weight: 1
        $x_1_2 = "t7Kt'Kt" ascii //weight: 1
        $x_1_3 = "Totota" ascii //weight: 1
        $x_1_4 = "Dochland Pochland" ascii //weight: 1
        $x_1_5 = "sutori wauu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_GB_2147747953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.GB!MTB"
        threat_id = "2147747953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 fb 29 0f 86 c2 00 00 00 83 fb 41 76 24 8b ce 8b c3 8b 75 0c 85 f6 0f 45 ce 33 d2 f7 f1 33 d2 b9 ab ff e3 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_VB_2147793371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.VB!MTB"
        threat_id = "2147793371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 12 ba 82 b4 3d 49 8a e8 d5 38 c1 fa 02 79}  //weight: 1, accuracy: High
        $x_1_2 = {42 6e 00 a8 89 c0 04 d8 d3 bf 04 30 89 c0 04 28 6e 74 ?? b8 88 c0 04 d0 7a ?? 00 40 88 c0 04 88 6f b6 04 c8 87 c0 04 b8 80 b6 04 50 87 c0 04 30 9a ?? ?? ?? ?? ?? ?? e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_PRD_2147793785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.PRD!MTB"
        threat_id = "2147793785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 e8 e9 d6 fc 5d 29 d2 81 c1 01 00 00 00 83 ec 04 c7 04 24 fc 4e f2 e2 5a 09 c2 81 f9 f4 01 00 00 75 05 b9 00 00 00 00 68 cb a4 60 7e 5a 83 ec 04 89 14 24 58 09 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_BL_2147794121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.BL!MTB"
        threat_id = "2147794121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bb 86 88 d6 00 09 c0 29 c1 40 e8 28 00 00 00 41 81 e8 d1 85 b2 6b 31 1e 89 c9 81 c6 02 00 00 00 21 c0 89 c8 39 d6 7c d8 81 c1 01 00 00 00 89 c9}  //weight: 1, accuracy: High
        $x_1_2 = {8d 1c 1f 81 c1 57 ce e8 e8 89 c1 09 c0 8b 1b 89 c0 81 e3 ff 00 00 00 81 e9 01 00 00 00 21 c0 47 40 68 f2 81 82 05 58 48 81 ff f4 01 00 00 75 05 bf 00 00 00 00 89 c8 01 c0 81 e9 ec d2 0f e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_AB_2147797754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.AB!MTB"
        threat_id = "2147797754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 34 aa 98 68 04 6e aa 6d 2c 41 66 0f ab d8 0f a4 d8 50 b8 6d f9 a7 65 f9 2b d2 f7 f1 f8 81 fd d5 6f d8 3d 31 05 58 ff 18 01 e9}  //weight: 1, accuracy: High
        $x_1_2 = {8b 04 b1 66 c1 ef 97 2b f9 89 4c 24 0c c1 d7 cd 66 0f bc c9 8d 04 28 c0 dd 63 89 6c 24 08 66 81 fc c0 47 bf ff ff ff ff 0f be 6c 38 01 41 83 c7 01 f5 b9 4e 6c 0c 27 0f be 0c 3b f9 3b e9 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_DER_2147797988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.DER!MTB"
        threat_id = "2147797988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 79 05 8b e9 3b c5 77 15 3b d5 72 11 8b ce 85 f6 75 08 89 3d 0c 5e 72 00 eb 03 89 7e 05 8b f1 8b cf 85 c9 75 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_INF_2147798663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.INF!MTB"
        threat_id = "2147798663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 d9 d3 ef 8b 4c 24 3c 8b 0c 8d 00 80 42 00 31 d1 8b 94 24 9c 00 00 00 89 bc 24 bc 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_AD_2147806303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.AD!MTB"
        threat_id = "2147806303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 06 83 f1 cd 89 4d e4 2d b9 da 65 00 a9 4b 00 00 00 74 03 89 45 d4 3d d7 e7 49 ab 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {8b c1 81 eb 00 80 41 98 89 45 e8 89 5d b8 8b 7d 0c 33 df 8b cb 3b cb 74 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_AF_2147806305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.AF!MTB"
        threat_id = "2147806305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 cc 6b 55 ec 00 8b 45 f4 2b c2 03 45 dc 2b 45 ec 05 99 14 00 00 33 45 fc 89 45 e4 0f b6 4d e0 03 4d f0 0f b6 55 f0 03 ca 83 e1 00 0f b7 45 e4 0b c8 89 4d dc 83 7d e8 00 75 09}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 45 fc 0f b7 4d e4 83 e1 00 33 4d f8 0b c1 89 45 dc 8b 55 f0 83 c2 1f 89 55 f0 6b 45 dc 00 0f b6 55 f8 8b 4d e4 03 4d d8 03 4d d4 0f b6 75 e0 2b ce d3 e2 33 c2 66 89 45 f4 6b 45 f8 00 89 45 f4 81 7d f0 0a 03 00 00 72 b5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_J_2147832369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.J!MSR"
        threat_id = "2147832369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "elf exe" ascii //weight: 1
        $x_1_2 = "heo8Movinggreatjimidst3whales" ascii //weight: 1
        $x_1_3 = "livingfrom.dstars" ascii //weight: 1
        $x_1_4 = "Formwere3they.re.Q" ascii //weight: 1
        $x_1_5 = "SGivemovingDFor.overhathspirit" ascii //weight: 1
        $x_1_6 = "kind1nDbeholdmovedfirstZZmoveth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_RDB_2147837019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.RDB!MTB"
        threat_id = "2147837019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 06 46 89 c0 32 02 47 88 47 ff 89 c0 42 52 83 c4 04 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 49}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptik_RDE_2147837020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptik.RDE!MTB"
        threat_id = "2147837020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "OneNeo" ascii //weight: 1
        $x_1_2 = "TwoNeo" ascii //weight: 1
        $x_1_3 = "ThrNeo" ascii //weight: 1
        $x_1_4 = "tidtcfvy.dll" ascii //weight: 1
        $x_2_5 = {8a 06 46 53 83 c4 04 89 c0 32 02 68 ?? ?? ?? ?? 83 c4 04 88 07 47 83 ec 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

