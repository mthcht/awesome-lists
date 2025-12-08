rule Trojan_Win32_Jaik_GIC_2147845971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.GIC!MTB"
        threat_id = "2147845971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 45 bc 49 c6 45 bd 6e c6 45 be 74 c6 45 bf 65 c6 45 c0 72 c6 45 c1 6e c6 45 c2 65 c6 45 c3 74 c6 45 c4 52 c6 45 c5 65 c6 45 c6 61 c6 45 c7 64 c6 45 c8 46 c6 45 c9 69 c6 45 ca 6c c6 45 cb 65}  //weight: 10, accuracy: High
        $x_1_2 = "cmd /c start C:\\ProgramData\\114514" ascii //weight: 1
        $x_1_3 = "cmd /c taskkill /f /t /im mmc.exe" ascii //weight: 1
        $x_1_4 = "C:\\ProgramData\\114514" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_MKV_2147847905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.MKV!MTB"
        threat_id = "2147847905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 45 bc 89 45 bc 8b 4d f0 8b 55 d0 8b 04 8a 33 05 ?? ?? ?? ?? 8b 4d f0 8b 55 d0 89 04 8a c7 45 c4 ac 39 00 00 8b 4d c4 83 c1 01 8b 45 c4 99 f7 f9 0f af 45 c4 89 45 c4 8b 55 f0 83 c2 01 89 55 f0 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_GPC_2147891513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.GPC!MTB"
        threat_id = "2147891513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b d7 2b d6 0f af 55 10 03 d3 0f af d3 6b d2 b2 01 95 d0 fc ff ff 8a c3 32 85 cb fc ff ff 66 83 3d 68 31 42 00 00 75 13}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_GMX_2147893482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.GMX!MTB"
        threat_id = "2147893482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 7a 5b 6b f4 f5 18 6d 66}  //weight: 10, accuracy: High
        $x_10_2 = {08 5d 2c 7d ?? 0b 96 ?? ?? ?? ?? 53 14 e7 32 6b 77 b9 ?? ?? ?? ?? 2d}  //weight: 10, accuracy: Low
        $x_1_3 = "b05jnlygj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_GNS_2147894653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.GNS!MTB"
        threat_id = "2147894653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {34 d8 13 0d ?? ?? ?? ?? 31 2b 79 31 f3 5a 8a c4 d0 c3}  //weight: 10, accuracy: Low
        $x_1_2 = "b4vNiR7Ca" ascii //weight: 1
        $x_1_3 = "P.vmp0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_GZA_2147901353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.GZA!MTB"
        threat_id = "2147901353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4c 24 14 03 4c 24 04 8b 6c 24 1c 03 2c 24 8a 11 8a 7d 00 30 fa 88 11 83 44 24 04 02 ff 04 24 8b 1c 24 8b 7c 24 20 4f 39 fb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_HNA_2147909117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.HNA!MTB"
        threat_id = "2147909117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 65 52 65 73 74 6f 72 65 50 72 69 76 69 6c 65 67 65 00 00 25 64 00 00 2e 74 6f 70 3a}  //weight: 1, accuracy: High
        $x_1_2 = {73 74 72 52 65 6d 6f 76 65 53 70 65 63 43 68 61 72 20 70 61 72 61 6d 20 65 72 72 6f 72 0a 00 00 32 31 34 37 34 38 33 36 35 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_HNB_2147923664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.HNB!MTB"
        threat_id = "2147923664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 65 74 50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 61 74 69 6f 6e 00 47 65 74 55 73 65 72 4f 62 6a 65 63 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 57 00 00 00 47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 00 00 47 65 74 41 63 74 69 76 65 57 69 6e 64 6f 77 00 4d 65 73 73 61 67 65 42 6f 78 57 00 55 00 53 00 45 00 52 00 33 00 32 00 2e 00 44 00 4c 00 4c 00 00 00 00 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 00 00 00 25 [0-48] 2e 64 61 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_MBXW_2147925116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.MBXW!MTB"
        threat_id = "2147925116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 6a ff 68 ?? e3 62 00 68 ?? 83 62 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? e1 62 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_MBXZ_2147925401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.MBXZ!MTB"
        threat_id = "2147925401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 6a ff 68 ?? e6 62 00 68 ?? 8a 62 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? e1 62 00 33 d2 8a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_NJ_2147925485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.NJ!MTB"
        threat_id = "2147925485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 45 e0 8d 14 00 8b 45 e4 01 d0 0f b7 00 66 83 f8 5c 75 ?? 8b 45 e0 8d 14 00 8b 45 e4 01 d0}  //weight: 3, accuracy: Low
        $x_2_2 = {83 ec 28 c7 45 d8 2a 00 00 00 8b 55 d8 8b 45 c8 c7 44 24 10 04 00 00 00 c7 44 24 0c 00 10 00 00 89 54 24 08 c7 44 24 04 00 00 00 00 89 04 24}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_MBWA_2147925622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.MBWA!MTB"
        threat_id = "2147925622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? c6 62 00 68 ?? 6a 62 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? c1 62 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_MBWA_2147925622_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.MBWA!MTB"
        threat_id = "2147925622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 6a ff 68 ?? d7 62 00 68 ?? 6a 62 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? d2 62 00 33 d2 8a d4 89 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_AMAC_2147926032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.AMAC!MTB"
        threat_id = "2147926032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 c8 80 e1 65 f6 d0 24 9a 08 c1 30 e1 88 0c 37 8b 7d ?? 8b 45 ?? 40 89 45 ?? 81 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_ARA_2147926725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.ARA!MTB"
        threat_id = "2147926725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 c2 02 00 91 ?? ?? 40 00 41 3b ce 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_ARA_2147926725_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.ARA!MTB"
        threat_id = "2147926725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 99 58 16 43 00 32 da 88 99 58 16 43 00 41 81 f9 db db 01 00 72 e9 33 c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_ARAZ_2147928718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.ARAZ!MTB"
        threat_id = "2147928718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 04 16 30 04 0b 83 c1 01 39 cd 75 e7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_NIT_2147931112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.NIT!MTB"
        threat_id = "2147931112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 70 0c 68 f0 00 00 00 ff 74 24 14 56 ff 15 f8 f2 4a 00 3b c7 74 19 50 56 ff 15 fc f2 4a 00 3b c7 75 04 33 c0 eb 11 50 ff 15 00 f3 4a 00 8b f8 57 8b cb e8}  //weight: 2, accuracy: High
        $x_2_2 = {8b 86 d0 00 00 00 8d 54 24 1c 50 50 52 c7 44 24 44 00 00 00 00 e8 11 f9 ff ff 8b 46 4c 8b 4e 48 83 c0 64 83 c4 0c 83 c1 64 89 44 24 08 8d 44 24 04 89 4c 24 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_TL_2147940841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.TL!MTB"
        threat_id = "2147940841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 1e 65 00 be 4a 6a 24 b6 4a 6a 24 7e 4a 6a 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_NH_2147943200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.NH!MTB"
        threat_id = "2147943200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "wwwww.php" ascii //weight: 2
        $x_1_2 = "exepayload\\http" wide //weight: 1
        $x_1_3 = {54 45 4d 50 [0-4] 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = "msslac.dll" ascii //weight: 1
        $x_1_5 = "INTERNET_OPTION_PASSWORD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_NH_2147943200_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.NH!MTB"
        threat_id = "2147943200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {85 f6 75 15 e8 91 f4 ff ff c7 00 ?? 00 00 00 e8 ac f3 ff ff 83 c8 ff eb 3c 8b 46 0c}  //weight: 2, accuracy: Low
        $x_1_2 = "agent" ascii //weight: 1
        $x_1_3 = "shutdown /r /t 0" ascii //weight: 1
        $x_1_4 = "Definec.exe" ascii //weight: 1
        $x_1_5 = "msslac.dll" ascii //weight: 1
        $x_1_6 = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\cbas.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_KK_2147947318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.KK!MTB"
        threat_id = "2147947318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {8b 8d e4 fd ff ff 03 c2 8b 95 e0 fd ff ff 0f b6 c0 0f b6 84 05 f0 fe ff ff 30 04 0a}  //weight: 30, accuracy: High
        $x_20_2 = {03 c8 81 e1 ff 00 00 80 79 ?? 49 81 c9 00 ff ff ff 41 8a 84 0d ?? ?? ?? ?? 88 84 3d 01 47 89 8d ?? ?? ff ff 88 9c 0d 02 81 ff}  //weight: 20, accuracy: Low
        $x_10_3 = "msgdeupdate.exe" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_ISR_2147947670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.ISR!MTB"
        threat_id = "2147947670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cndom6.sys" ascii //weight: 1
        $x_1_2 = "XiaoH.sys" ascii //weight: 1
        $x_1_3 = "Add-MpPreference -ExclusionPath 'C:\\\\Users\\\\Public\\\\Documents" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_BAA_2147957548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.BAA!MTB"
        threat_id = "2147957548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 0f f6 d0 c0 c8 04 34 58 88 04 0f 41 3b ca 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_AHB_2147959010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.AHB!MTB"
        threat_id = "2147959010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {89 c8 c1 e0 ?? 31 c1 89 d0 c1 f8 ?? 89 cb 31 d0 c1 fb ?? 31 c8 8d 8d 20 ff ff ff 31 c3}  //weight: 30, accuracy: Low
        $x_20_2 = {ff 0f a4 c2 ?? c1 e0 ?? 29 c6 8b 45 10 19 d7 99 8b 85 e4 fe ff ff 0f af c2}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Jaik_AJK_2147959020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaik.AJK!MTB"
        threat_id = "2147959020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 34 86 0f b7 04 47 03 f1 8b 3c 82 8b c6 03 f9 b9 fc 2c 01 10 8a 10 3a 11 75 1a 84 d2 74 12 8a 50 01 3a 51 01}  //weight: 3, accuracy: High
        $x_2_2 = {68 7c 2d 01 10 8d 44 24 54 50 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 20 6a 01 6a 01 68 80}  //weight: 2, accuracy: Low
        $x_1_3 = "silver\\hack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

