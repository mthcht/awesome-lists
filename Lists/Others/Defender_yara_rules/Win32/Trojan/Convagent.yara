rule Trojan_Win32_Convagent_DS_2147782380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.DS!MTB"
        threat_id = "2147782380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 56 c4 08 00 01 45 fc 8b 15 24 90 48 00 03 55 08 8b 45 fc 03 45 08 8a 08 88 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_DS_2147782380_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.DS!MTB"
        threat_id = "2147782380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 d6 8b c5 14 08 84 9e 04 33 5a 5d 5f ee db c2 73 87 6f 5a f8 ba 8b fb 8b 32 4b 7b 7b 7b e1 3b f0 72 0b ce 03 4a 35 e8 03 6b 67 cd 77 62 11 bc 75 6d 7b 75 1b 8b b7 01 1b 05 29 51 83 7b 0c ec b7 83 2d 3b 48 61 eb 3f 2c 8b 7a 04 03}  //weight: 1, accuracy: High
        $x_1_2 = {13 96 bf 49 04 6a 01 68 00 20 56 bf 80 8b f8 89 3b 85 ff 74 b0 1d 66 f8 23 8b d3 b8 d8 47 63 13 24 80 7c 58 f7 fd e3 8b 03 50 26 88 f8 03 63 55 8b d9 7d 63 bf 37 b3 e8 c7 43 04 60 6a 04 4f 68 0b 55 4d 8e}  //weight: 1, accuracy: High
        $x_1_3 = {85 88 0a c7 05 b4 df 87 f1 72 45 84 10 df 81 fb 58 75 5b 5b 72 db a7 8b 2f 04 75 08 7c 37 bf 19 eb 5a a3 7d 0e 8b 82 4a 79 48 2b 96 80 b1 3d 9c 0d ae ab 14 27 b7 ed 3f d8 f4 b7 8b d0 8b}  //weight: 1, accuracy: High
        $x_1_4 = {13 c1 8d 39 d3 90 3c 10 5e d3 2c a1 1d a5 55 22 2b 49 1d 80 5d cf 89 3d cd b2 b1 83 c6 ec e6 fe be 8b 3c 53 0b 5b 48 ed 63 7d d7 a9 cd a5 0b 1d 71 c7 c7 3b fe f8 b0 01 14 5a ea 6c b5 2f 0a 48 83 ce d6 a6 46 68 38 e7 7b 0a 38 0a 46 07 31 0a 71 5d 7d}  //weight: 1, accuracy: High
        $x_1_5 = {18 17 90 9e c5 27 13 03 35 23 4f fd 71 21 c6 01 36 27 00 25 26 0b f0 89 eb 22 04 6b d9 f8 d4 94 df b0 0c 60 a8 e1 4d 82 c2 a9 0e a2 01 9b da 02 3b c4 7d 0e ad 13 4a b8 d7 9d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_CD_2147816736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.CD!MTB"
        threat_id = "2147816736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dxSougou.dll" ascii //weight: 1
        $x_1_2 = "4399.com" ascii //weight: 1
        $x_1_3 = "C:\\Windows\\MyTxt2.txt" wide //weight: 1
        $x_1_4 = "kankan.com" ascii //weight: 1
        $x_1_5 = "www.xxxxx.com" ascii //weight: 1
        $x_1_6 = "www.jjj.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_VP_2147819553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.VP!MTB"
        threat_id = "2147819553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {85 40 00 58 81 c7 ?? ?? ?? ?? 01 d7 e8 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 31 01 01 ff 41 01 d2 39 f1 75 dc 21 fa 4a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_NV_2147819806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.NV!MTB"
        threat_id = "2147819806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 58 89 c9 e8 ?? ?? ?? ?? 31 07 68 ?? ?? ?? ?? 5b 01 c9 81 c7 ?? ?? ?? ?? 01 c9 68 ?? ?? ?? ?? 59 39 f7 75 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_VW_2147819840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.VW!MTB"
        threat_id = "2147819840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f8 83 25 24 4d 46 00 00 33 c3 2b f8 89 7d e0 8b 45 d4 29 45 fc ff 4d e4 0f 85 ?? ?? ?? ?? 8b 45 e8 89 3e 5f 89 46 04 5e 5b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AU_2147820071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AU!MTB"
        threat_id = "2147820071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4c 04 58 8b 54 24 54 01 c2 31 ca 88 54 04 58 83 c0 01 83 f8 ?? 75 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {89 f8 88 44 24 ?? 83 c6 02 83 f6 ?? 89 f0 88 44 24 ?? 83 c3 03 83 f3 ?? 88 5c 24 ?? 83 c1 04 83 f1 ?? 88 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AV_2147820311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AV!MTB"
        threat_id = "2147820311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 2c a2 86 7a 5c c7 45 68 6e b7 1b 45 c7 85 [0-4] af 55 a9 41 89 55 70 b8 3b 2d 0b 00 01 45 70 8b 45 70 8a 04 30 88 04 0e 46 3b 35 [0-4] 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 b8 39 61 cd 71 c7 45 74 66 25 52 4c c7 45 60 92 48 22 70 c7 45 18 7f 17 c5 44 c7 45 20 f6 01 72 35 c7 45 c4 f0 4e f3 3e}  //weight: 1, accuracy: High
        $x_1_3 = {81 ff a7 b4 e7 00 7f 0d 47 81 ff e2 99 4e 5d 0f 8c}  //weight: 1, accuracy: High
        $x_1_4 = "worms.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_DD_2147822832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.DD!MTB"
        threat_id = "2147822832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 3a 00 74 f8 90 ac 32 02 aa 42 e2 f3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_BD_2147822884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.BD!MTB"
        threat_id = "2147822884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {97 08 18 78 64 81 50 07 e8 eb 46 86 d9 01 92 86 1b 31 ac d0 40 a1 0f 90 d0 97 88 1e e0 80 c1 02 2e ac e1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_BD_2147822884_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.BD!MTB"
        threat_id = "2147822884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UnregisterClassA" ascii //weight: 1
        $x_1_2 = "C:\\Bugreport_error.ini" wide //weight: 1
        $x_1_3 = "njjoc" ascii //weight: 1
        $x_1_4 = "WAqrrsif" ascii //weight: 1
        $x_1_5 = "DLL ERROR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_A_2147826892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.A!MTB"
        threat_id = "2147826892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 5d a0 d0 66 f7 a4 24 80 00 00 00 8b 84 24 80 00 00 00 81 ac 24 80 00 00 00 d6 8a cd 68 b8 e2 3f 96 6e f7 a4 24 80 00 00 00 8b 84 24 80 00 00 00 81 84 24 80 00 00 00 86 7c 61 60 8a 84 37 3b 2d 0b 00 88 04 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_XB_2147829361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.XB!MTB"
        threat_id = "2147829361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 f0 8b 08 89 4d e0 8b 55 f0 8b 02 c1 e0 06 8b 4d f0 8b 11 c1 ea 08 33 c2 8b 4d f0 8b 09 03 c8 8b 45 f8 33 d2 f7 75 e4 8b 45 d8 03 0c 90 03 4d f8 8b 55 e8 8b 02 2b c1 8b 4d e8 89 01 8b 55 f0 8b 45 e8 8b 08 89 0a 81 3d}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_EM_2147829595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.EM!MTB"
        threat_id = "2147829595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 45 ec 88 02 c7 85 a8 fa ff ff 02 00 00 00 8b 45 ec 33 d2 b9 58 02 00 00 f7 f1 8b 85 38 fd ff ff 03 45 ec 8a 8c 15 64 fd ff ff 88 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_EN_2147829599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.EN!MTB"
        threat_id = "2147829599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Helxsyu1!" ascii //weight: 1
        $x_1_2 = "SHe;!" ascii //weight: 1
        $x_1_3 = "Does it work!L" ascii //weight: 1
        $x_1_4 = "YHUAsgyu" ascii //weight: 1
        $x_1_5 = "WkuxzgsX{t{jgu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_EN_2147829599_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.EN!MTB"
        threat_id = "2147829599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svgsjigj49hoihjri" ascii //weight: 1
        $x_1_2 = "sogijs489sh5rjiho jh i + i" ascii //weight: 1
        $x_1_3 = "fork8.dll" ascii //weight: 1
        $x_1_4 = "VerifyVersionInfoA" ascii //weight: 1
        $x_1_5 = "iAT5BikygwI4J7cVKAq0mWdI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_DE_2147829954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.DE!MTB"
        threat_id = "2147829954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8a 04 02 32 04 19 88 03 8d 45 90 50 ff d6}  //weight: 4, accuracy: High
        $x_2_2 = "62.204.41.126" ascii //weight: 2
        $x_2_3 = "51.195.166.189" ascii //weight: 2
        $x_2_4 = "168.119.59.211" ascii //weight: 2
        $x_1_5 = "Bitcoin\\wallets" ascii //weight: 1
        $x_1_6 = "Downloads\\%s_%s.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Convagent_RPM_2147833024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.RPM!MTB"
        threat_id = "2147833024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 fa 04 89 c8 c1 f8 1f 29 c2 89 d0 ba 4b 00 00 00 0f af c2 89 c1 8b 55 ec 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 ec 01 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AZ_2147833391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AZ!MTB"
        threat_id = "2147833391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DubiboKozoqo" ascii //weight: 1
        $x_1_2 = "FmDeamNZSiPZBhBEiNbEpU" ascii //weight: 1
        $x_1_3 = "LYzkdLNZMxLryufcuHrZfS" ascii //weight: 1
        $x_1_4 = "gOJuqesQGIHarfHDmgApkY" ascii //weight: 1
        $x_1_5 = "kHKsCJrSEzOUcHvbDJpxnx" ascii //weight: 1
        $x_1_6 = "fork2.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AG_2147833866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AG!MTB"
        threat_id = "2147833866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AGeIMplhnntzqftIp" ascii //weight: 1
        $x_1_2 = "OkoxlPoqaju" ascii //weight: 1
        $x_1_3 = "PHTaLBIgjvpMtvExj" ascii //weight: 1
        $x_1_4 = "ZVKjxZhGxssOOUofz" ascii //weight: 1
        $x_1_5 = "lpNhDrWBreeGXBJaF" ascii //weight: 1
        $x_1_6 = "fork2.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_BH_2147837442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.BH!MTB"
        threat_id = "2147837442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b d0 8d 45 ec 03 c7 0f be 04 78 33 c8 0f be 44 5d ec 33 c8 8b 45 e4 0f be 44 05 ec 33 c8 8b 45 dc 33 d1 8b 4d e8 33 55 e0 31 14 08 83 c1 04 89 4d e8 3b 4d 1c 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_SPQ_2147837554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.SPQ!MTB"
        threat_id = "2147837554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {89 44 8f e4 8b 44 8e e8 89 44 8f e8 8b 44 8e ec 89 44 8f ec 8b 44 8e f0 89 44 8f f0 8b 44 8e f4 89 44 8f f4 8b 44 8e f8 89 44 8f f8 8b 44 8e fc 89 44 8f fc 8d 04 8d 00 00 00 00 03 f0 03 f8 ff 24 95 a0 c8 55 00}  //weight: 3, accuracy: High
        $x_2_2 = "moyun/Data/ESP_NG.datPK" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_EC_2147842344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.EC!MTB"
        threat_id = "2147842344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {0f be 04 10 6b c0 31 99 b9 24 00 00 00 f7 f9 83 e0 02 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_ACG_2147843053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.ACG!MTB"
        threat_id = "2147843053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 50 57 ff d3 85 c0 75 ?? 83 fe 28 0f 8e ?? ?? ?? ?? 8d 44 24 1c 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_ACG_2147843053_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.ACG!MTB"
        threat_id = "2147843053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 54 34 28 0f b6 84 34 28 01 00 00 03 d8 0f b6 ca 03 d9 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 8a 44 1c 28 88 44 34 28 46 88 54 1c 28 81 fe}  //weight: 1, accuracy: High
        $x_3_2 = {0f b6 44 1c 28 88 44 34 28 88 4c 1c 28 0f b6 44 34 28 8b 4c 24 0c 03 c2 8b 54 24 10 0f b6 c0 0f b6 44 04 28 32 44 39 08 88 04 0a 41}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_RPX_2147843544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.RPX!MTB"
        threat_id = "2147843544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 e8 00 00 00 00 5d 50 51 0f ca f7 d2 9c f7 d2 0f ca eb 0f b9 eb 0f b8 eb 07 b9 eb 0f 90 eb 08 fd eb 0b f2 eb f5 eb f6 f2 eb 08 fd}  //weight: 1, accuracy: High
        $x_1_2 = "godzmu" wide //weight: 1
        $x_1_3 = "KAMERsUCKSsKAMERsUCKS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_MKV_2147847752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.MKV!MTB"
        threat_id = "2147847752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d8 88 45 ?? 0f b6 4d ?? 83 e9 4d 88 ?? df 0f b6 55 ?? 83 f2 50 88 55 ?? 0f b6 45 df 83 e8 4e 88 45 df 0f b6 4d df f7 d9 88 4d ?? 0f b6 55}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 d8 88 45 ?? 0f b6 4d ?? 81 f1 ?? ?? ?? ?? 88 4d df 0f b6 55 ?? 81 c2 ?? ?? ?? ?? 88 55 df 0f b6 45 ?? 83 f0 2b 88 45 ?? 0f b6 4d ?? 83 e9 01 88 4d ?? 8b 55 e0 8a 45 ?? 88 44 15 e4 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_PA_2147847762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.PA!MTB"
        threat_id = "2147847762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d2 88 95 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? 83 c0 ?? 88 85 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? c1 f9 ?? 0f b6 95 ?? ?? ?? ?? c1 e2 ?? 0b ca 88 8d ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? 2b 85 ?? ?? ?? ?? 88 85 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? f7 d1 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? f7 da 88 95}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_GJT_2147850300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.GJT!MTB"
        threat_id = "2147850300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 45 e7 62 c6 45 db 68 c6 45 d4 38 c6 45 e9 67 c6 45 e3 52 c6 45 eb 34 c6 45 e8 48 c6 45 d9 64 c6 45 cf 49 c6 45 d7 67 c6 45 d2 38 c6 45 e5 41 c6 45 d0 34 c6 45 e2 55 c6 45 e4 4b c6 45 ea 31 c6 45 de 76 c6 45 d8 43 c6 45 d3 54 c6 45 ce 79 c6 45 d5 35 c6 45 dd 53 c6 45 cc 52 c6 45 dc 6c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_CH_2147851797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.CH!MTB"
        threat_id = "2147851797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {da b6 e9 46 76 e9 5e 76 db ae f3 eb 16 64 65 65 b6 65 b9 8e e9 5e 66 db 9f ce 66 67 66 66 f3 eb 16 63 65 65 b6 65 b9 7e f3 eb 16 63 65 65 b6 d0 66 d0 66 b6 65 b9 92 f3 eb 16 63 65 65 b6 65 b9 9a f3 eb 16 63}  //weight: 1, accuracy: High
        $x_1_2 = {e7 a1 b3 c0 db 5b f1 59 69 d9 a2 e7 a4 b6 ab 66 66 db 4e f1 29 c1 29 bb f1 52 e9 2a 4e b9 f1 c3 76 bc 99 26 9f ab 72 bd f1 e3 7a ef 6d 2d ab 56 66 62 65 65 ef c3 52 75 ec a4 67 66 66 51 69}  //weight: 1, accuracy: High
        $x_1_3 = {8d 8c 24 8c 00 00 00 c6 84 24 98 00 00 00 1d e8 9d 02 00 00 8b 44 24 20 50 ff d3 83 c4 04 3b f5 8b c8 75 28 3b cd 75 24 8b 1d 78 31 40 00 6a 10 ff d3 99 2b c2 6a 11 8b f0 d1 fe ff d3 6a 04 8b e8 ff d3 03 c5 99 2b c2}  //weight: 1, accuracy: High
        $x_1_4 = {a6 a1 37 75 ea 41 66 66 66 f1 bb 56 a1 37 e2 6d 69 39 ef bb 62 51 74 e7 60 66 62 65 65 ef c3 62 e3 69 ef b3 62 99 38 ef b3 5e f1 5e 27 55 69 f1 a2 a4 f1 2e e9 47 6d 39 55 f1 30 e9 4d 67 39 4d 6f e3 5e a8 a6 e9 60 70}  //weight: 1, accuracy: High
        $x_1_5 = "UI\\canvas.bmp" ascii //weight: 1
        $x_1_6 = "XMediaUIFactory.dll" ascii //weight: 1
        $x_1_7 = "ucast.com.cn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_GMB_2147853100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.GMB!MTB"
        threat_id = "2147853100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 04 88 18 c6 40 01 00 5b c3 ?? 8b 44 24 04 b9 01 00 00 00 8b 10 83 c0 04 85 d2 7e ?? 56 8b 30 83 c0 04 0f af ce 4a 75 ?? 8b 54 24 0c 5e 89 0a c3 8b 54 24 08 89 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_DX_2147853398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.DX!MTB"
        threat_id = "2147853398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {50 8d 45 fc 50 8b 45 fc 8d 04 86 50 56 57 e8 [0-4] 8b 45 fc 83 c4 14 48 89 35 a8 bc 45 01 5f 5e a3 a4 bc 45 01 5b c9}  //weight: 3, accuracy: Low
        $x_1_2 = "SteamService.exe" wide //weight: 1
        $x_1_3 = ".i814" ascii //weight: 1
        $x_1_4 = ".i815" ascii //weight: 1
        $x_1_5 = ".i816" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Convagent_GMC_2147887403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.GMC!MTB"
        threat_id = "2147887403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 04 01 00 00 56 53 ff 15 ?? ?? ?? ?? a1 98 ?? 45 01 89 35 c0 ?? 45 01 8b fe 38 18}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 fc 83 c4 14 48 89 35 a8 ?? 45 01 5f 5e a3 a4 ?? 45 01 5b}  //weight: 10, accuracy: Low
        $x_1_3 = "SteamService.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_MBIN_2147890022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.MBIN!MTB"
        threat_id = "2147890022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 eb 33 e8 2b fd 8b d7 c1 e2 04 89 54 24 10 8b 44 24 ?? 01 44 24 10}  //weight: 1, accuracy: Low
        $x_1_2 = {69 77 69 6d 75 00 00 64 61 76 6f 77 75 66 61 62 6f 79 69 78 69 70 69 6a 6f 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_RPY_2147890448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.RPY!MTB"
        threat_id = "2147890448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5c 24 18 8b c5 c1 e0 04 03 44 24 2c 8b f5 03 dd c1 ee 05 89 44 24 14}  //weight: 1, accuracy: High
        $x_1_2 = {33 f3 33 f0 2b fe 8b d7 c1 e2 04 89 54 24 14 8b 44 24 28 01 44 24 14 8b 5c 24 18}  //weight: 1, accuracy: High
        $x_1_3 = {8b 44 24 14 33 f3 33 c6 2b e8 89 44 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AMAB_2147892065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AMAB!MTB"
        threat_id = "2147892065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 df 33 d8 2b f3 8b d6 c1 e2 04 89 54 24 10 8b 44 24 24 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00}  //weight: 5, accuracy: Low
        $x_5_2 = {33 cf 31 4c 24 10 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 10 29 44 24 14}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AMAA_2147892236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AMAA!MTB"
        threat_id = "2147892236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 eb 33 e8 2b f5 8b d6 c1 e2 04 89 54 24 ?? 8b 44 24 ?? 01 44 24}  //weight: 5, accuracy: Low
        $x_5_2 = {33 d3 31 54 24 14 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 14 29 44 24 18}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AMBA_2147892859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AMBA!MTB"
        threat_id = "2147892859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 04 13 d3 ea 89 45 ec c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 e0 8b 45 ec 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 ec 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_DY_2147895072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.DY!MTB"
        threat_id = "2147895072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "55447F28E92CF435D8D682E6B0467B39CB7498032BDA020316DF88CDF" ascii //weight: 2
        $x_1_2 = "467356467355555754466466755" ascii //weight: 1
        $x_1_3 = "2F8761CF148F88C2640DBBA783EF2917" ascii //weight: 1
        $x_1_4 = "c:\\jc.txt" ascii //weight: 1
        $x_1_5 = "122.224.51.149" ascii //weight: 1
        $x_1_6 = "web.aqdcj.com/yong/58.h" ascii //weight: 1
        $x_1_7 = "rec\\Irrlicht.dll" ascii //weight: 1
        $x_1_8 = "61.92.48.59" ascii //weight: 1
        $x_1_9 = "8000126.com" ascii //weight: 1
        $x_1_10 = "jinyusheng.com" ascii //weight: 1
        $x_1_11 = "134022524324422532435444435" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_RR_2147895840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.RR!MTB"
        threat_id = "2147895840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8d 85 00 fc ff ff 50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00 8b 85 f8 fe ff ff 50 e8}  //weight: 1, accuracy: High
        $x_1_2 = {50 8b 85 48 fc ff ff 50 e8 ?? ?? ?? ?? 83 f8 01 1b c0 40 88 85 f3 fe ff ff 8b 85 48 fc ff ff 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_CCEM_2147897345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.CCEM!MTB"
        threat_id = "2147897345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f a4 c9 0e 0f b6 82 ?? ?? ?? ?? 33 c1 88 04 14 42 0f be d2 83 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_NC_2147897373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.NC!MTB"
        threat_id = "2147897373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {72 f4 8a 85 ee fa ff ff c6 85 fc fe ff ff 20 84 c0 74 2e 8d 9d ef fa ff ff 0f b6 c8 0f b6 03 3b c8 77 16 2b c1}  //weight: 3, accuracy: High
        $x_1_2 = "Dihybrids.exe" wide //weight: 1
        $x_1_3 = "LoadResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_NC_2147897373_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.NC!MTB"
        threat_id = "2147897373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Please Run As Ulang Atau Restart Komputer Anda Atau Matikan Antivirus Anda" ascii //weight: 2
        $x_1_2 = "Sukses Inject" ascii //weight: 1
        $x_2_3 = "vip-fnatic.com" ascii //weight: 2
        $x_2_4 = "api-vvipmods.com" ascii //weight: 2
        $x_1_5 = "Harap Buka Ulang Tools Injection Atau Hubungi Seller !" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_GAB_2147898579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.GAB!MTB"
        threat_id = "2147898579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 30 0f af 00 00 01 cd 8b 48 2c}  //weight: 10, accuracy: High
        $x_10_2 = {00 cd 8b 48 54 0f af 4e 00 00 cd 8b 48 50}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_GAC_2147898678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.GAC!MTB"
        threat_id = "2147898678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 01 00 00 00 43 ef 6d 00 ba ?? ?? ?? ?? be ?? ?? ?? ?? 49 b9 ?? ?? ?? ?? 00 0a 01 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AMAF_2147901599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AMAF!MTB"
        threat_id = "2147901599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b 45 0c 50 0f b6 4d 08 51 e8 ?? ?? ?? ?? 83 c4 08 8b f0 8b 55 0c 52 0f b6 45 08 50 e8 ?? ?? ?? ?? 83 c4 08 25 00 00 00 f0 c1 e8 17 33 c6 5e 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_YA_2147902029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.YA!MTB"
        threat_id = "2147902029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "httpdropper-master\\Release\\DropperV2.pdb" ascii //weight: 1
        $x_1_2 = "/config" ascii //weight: 1
        $x_1_3 = "/Tenio" ascii //weight: 1
        $x_1_4 = {8b 07 3b 45 fc 74 f2 33 c2 8b 55 fc d3 c8 8b c8 89 17 89 45 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_SPXX_2147903231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.SPXX!MTB"
        threat_id = "2147903231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 ec 04 08 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 00 08 00 00 a1 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 9e 13 00 00 a3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_ZK_2147905465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.ZK!MTB"
        threat_id = "2147905465"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 d3 e8 03 45 d0 89 45 f0 33 45 e4 31 45 fc 8b 45 fc 29 45 f8 81 c7 ?? ?? ?? ?? 89 7d ec 4e 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_SPDD_2147908241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.SPDD!MTB"
        threat_id = "2147908241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 89 0d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 30 14 1e 83 ff 0f 75 29}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_FIT_2147909265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.FIT!MTB"
        threat_id = "2147909265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 64 89 44 24 0c 83 6c 24 0c ?? 8a 54 24 0c 8b 44 24 10 30 14 30 83 ff 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_ASGD_2147911700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.ASGD!MTB"
        threat_id = "2147911700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff 59 8b 45 ?? 83 c0 64 89 45 ?? 83 6d ?? 64 8b 45 bc 8a 4d ?? 03 c7 30 08 83 fb 0f 75}  //weight: 4, accuracy: Low
        $x_1_2 = {46 81 fe cb ed 36 00 0f 8c ?? ?? ff ff 5e c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AMMI_2147911935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AMMI!MTB"
        threat_id = "2147911935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 30 08 83 fb 0f 75 ?? 6a 2e 8d 45 cc}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 37 83 7d 08 0f 75 ?? 6a 2e 8d 45 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Convagent_AMMI_2147911935_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AMMI!MTB"
        threat_id = "2147911935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 [0-5] 33 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_REV_2147914047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.REV!MTB"
        threat_id = "2147914047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f8 8b c7 c1 e8 05 03 d7 89 45 6c 8b 85 ?? ?? ?? ?? 01 45 6c 8b f7 c1 e6 04 03 b5 b0 fd ff ff 33 f2 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_SPON_2147914287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.SPON!MTB"
        threat_id = "2147914287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f8 50 89 75 f8 e8 ?? ?? ?? ?? 8a 45 f8 30 04 3b 83 7d 08 0f 59 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_MGZ_2147914570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.MGZ!MTB"
        threat_id = "2147914570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 54 24 24 8b 4c 24 3c 8b 74 24 30 03 0a 0f b6 06 30 01 8b c2 8b 4c 24 2c 2b ca 83 e1 fc 81 f9 00 10 00 00 72 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AMAI_2147914751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AMAI!MTB"
        threat_id = "2147914751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c 86 0f b6 04 07 6a ?? 30 04 11 b9 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_ZT_2147915288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.ZT!MTB"
        threat_id = "2147915288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 c1 e0 04 03 85 ?? ?? ?? ?? 33 c1 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 45 ?? 31 85 ?? ?? ?? ?? 2b b5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AMAM_2147915704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AMAM!MTB"
        threat_id = "2147915704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 34 88 8b 4a ?? 8b 44 24 ?? 8a 04 01 b9 ?? ?? ?? ?? 30 04 2e e8 ?? ?? ?? ?? 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_BAO_2147915840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.BAO!MTB"
        threat_id = "2147915840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 89 bd f8 f7 ff ff e8 ?? ?? ?? ?? 8b 85 f4 f7 ff ff 59 8a 8d f8 f7 ff ff 03 c6 30 08 83 fb 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AMAN_2147915855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AMAN!MTB"
        threat_id = "2147915855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 34 88 8b 4a ?? 8b 44 24 ?? 8a 04 01 8b 4c 24 ?? 30 04 0e 8d 4c 24 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AMAQ_2147916440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AMAQ!MTB"
        threat_id = "2147916440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 59 8a 4d ?? 30 08 46 3b f7 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_QAA_2147916452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.QAA!MTB"
        threat_id = "2147916452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 70 8b 45 70 03 85 10 ff ff ff 8d 14 3b 33 c2 33 c1 29 85 1c ff ff ff 83 3d 94 58 0f 02 0c c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 70 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_MMZ_2147919248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.MMZ!MTB"
        threat_id = "2147919248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 f8 83 c0 46 89 45 fc 83 6d fc ?? 83 6d fc 3c 8b 45 08 8a 4d fc 03 c7 30 08 47 3b fb 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_CZ_2147919511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.CZ!MTB"
        threat_id = "2147919511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b cb c1 e9 ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b f3 c1 e6 ?? 03 74 24 ?? 8d 14 1f 33 f2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AGT_2147919895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AGT!MTB"
        threat_id = "2147919895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {55 8b ec 83 ec 10 53 56 57 a0 ?? ?? ?? 00 32 05 ?? ?? ?? 00 a2 ?? ?? ?? 00 33 c9 8a 0d ?? ?? ?? 00 c1 f9 03 83 c9 01 89 4d f0}  //weight: 3, accuracy: Low
        $x_2_2 = {c1 e1 04 8b 15 ?? ?? ?? 00 23 d1 89 15 ?? ?? ?? 00 33 c0 a0 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 83 e1 08 0f af c1 8b 15 ?? ?? ?? 00 0b d0 89 15 ?? ?? ?? 00 e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AGH_2147920402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AGH!MTB"
        threat_id = "2147920402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d6 d1 ea 03 c2 33 d2 a3 ?? ?? ?? 00 83 e0 07 8a d1 68 ?? ?? ?? 00 0f af c2 03 f0 89 35 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 85 c0 89 07 5e}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 83 ec 10 53 56 57 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 83 c4 04 e9}  //weight: 2, accuracy: Low
        $x_1_3 = {57 8d 0c 85 00 00 00 00 6a 00 0b ca 89 4c 24 08 df 6c 24 08}  //weight: 1, accuracy: High
        $x_3_4 = {32 c8 8b 15 ?? ?? ?? 00 88 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 80 c9 0c 53 c0 e9 02 81 e1 ff 00 00 00 52 89 4c 24 08 db 44 24 08 dc 3d}  //weight: 3, accuracy: Low
        $x_2_5 = {83 ca 02 2b da 8b 15 ?? ?? ?? 00 89 1d ?? ?? ?? 00 33 db 8a 1d ?? ?? ?? 00 83 ca 01 0f af d3 33 ca 68 ?? ?? ?? 00 50 89 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Convagent_RZ_2147920499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.RZ!MTB"
        threat_id = "2147920499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c3 c1 e8 05 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 03 4d ?? c1 ?? 04 03 5d ?? 33 d9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AMO_2147923434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AMO!MTB"
        threat_id = "2147923434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ca 8b 45 ?? c1 e8 05 89 45 ?? 8b 45 ?? 33 f1 8b 4d ?? 03 c1 33 c6 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_CCJT_2147929903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.CCJT!MTB"
        threat_id = "2147929903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 45 dc e1 32 41 00 89 75 e0 89 75 e4 89 45 e8 ff 15}  //weight: 2, accuracy: High
        $x_1_2 = {8b 85 1c ff ff ff 05 3f 03 00 00 ff e0}  //weight: 1, accuracy: High
        $x_1_3 = {b9 be f9 ff ff f7 d1 e8 00 00 00 00 5a 83 c2 11 92 bb 1b 84 44 1b 31 18 83 c0 04 e2 f9 4e 0f a8}  //weight: 1, accuracy: High
        $x_1_4 = {17 90 f4 58 28 d2 0f 02 13 90 fa 64 90 2d e2 7d 54 03 f1 b6 73 a9 76 a6 ef 73 b6 30 8a 17 ec c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_ADIA_2147929917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.ADIA!MTB"
        threat_id = "2147929917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d3 c1 ea 05 03 cb 89 55 ?? 8b 45 ?? 01 45 ?? 8b c3 c1 e0 04 03 45 ?? 33 45 ?? 33 c1 2b f8 89 7d ?? 8b 45 ?? 29 45 ?? 83 6d ?? 01 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_NG_2147931427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.NG!MTB"
        threat_id = "2147931427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Sukses Inject" ascii //weight: 2
        $x_2_2 = "koalabaper.com" ascii //weight: 2
        $x_2_3 = "vip-fnatic.com" ascii //weight: 2
        $x_1_4 = "DLL Injected" ascii //weight: 1
        $x_1_5 = "Harap Buka Ulang Tools Injection Atau Hubungi Seller" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_BAA_2147936776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.BAA!MTB"
        threat_id = "2147936776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 49 0e 2b c1 85 c0 74 ?? a1 ?? ?? ?? ?? 05 88 13 00 00 a3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_BAB_2147940674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.BAB!MTB"
        threat_id = "2147940674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b9 07 00 00 00 c1 c0 04 24 0f 04 41 88 06 46 e2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_PGC_2147940786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.PGC!MTB"
        threat_id = "2147940786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f 42 d8 f6 c1 7f b9 ?? ?? ?? ?? 89 5d a0 0f 95 c1 0f b6 db f6 c3 7f 89 5d a8 b8 ?? ?? ?? ?? 0f 95 c0 03 c8 8b 45 9c c1 e8 07 03 c8 8b c3}  //weight: 2, accuracy: Low
        $x_3_2 = "NYGpuKKiU7?[0kt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_BAC_2147941284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.BAC!MTB"
        threat_id = "2147941284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 8d 0c 1a 8d 42 01 42 30 01 81 fa ?? ?? ?? ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_EGD_2147942198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.EGD!MTB"
        threat_id = "2147942198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4c 24 1c 8b c5 2b cd 8b fe 8a 1c 01 30 18 40 4f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_EGRP_2147943985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.EGRP!MTB"
        threat_id = "2147943985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 55 fc 0f be 02 83 f0 34 8b 4d f8 03 4d fc 88 01 ?? ?? ba 01 00 00 00 6b c2 42 8b 4d f8 c6 04 01 00 8b 45 f8 8b e5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_EUHE_2147943988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.EUHE!MTB"
        threat_id = "2147943988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c1 e9 05 03 4d d4 33 d1 8b 45 e0 2b c2 89 45 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_BAD_2147944384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.BAD!MTB"
        threat_id = "2147944384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 45 fe 03 c2 88 45 ?? 0f b6 4d ?? 8b 55 ?? 2b d1 89 55 ?? 0f b6 45 ?? 03 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_AGC_2147949644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.AGC!MTB"
        threat_id = "2147949644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e4 8d 55 e8 33 f6 52 89 75 e8 8b 08 56 50 ff 51 24 85 c0 79 0f 6a 10 68 00 3f 41 00 68 f4 3f 41 00 56}  //weight: 1, accuracy: High
        $x_2_2 = {85 c0 78 58 8b 45 ec 8d 55 d4 52 89 75 d4 68 ?? ?? ?? ?? 8b 08 50 ff 11 85 c0 78 37 53 8d 4d c8}  //weight: 2, accuracy: Low
        $x_3_3 = {8d 75 94 8d 7d 84 a5 8d 4d c4 68 54 40 41 00 a5 a5 a5 e8 ?? ?? ?? ?? c6 45 fc 0b 8b 10 85 d2}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Convagent_KK_2147951395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Convagent.KK!MTB"
        threat_id = "2147951395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 85 c0 0f 84 ?? ?? 00 00 0f 10 05 ?? ?? 03 00 0f 11 40 1a 0f 10 05 ?? ?? 03 00 0f 11 40 10 0f 10 05 ?? ?? 03 00 48 89 85 ?? 05 00 00 0f 11 00 48 8d 4d}  //weight: 10, accuracy: Low
        $x_5_2 = "Freelancer_Contract_Viewer.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

