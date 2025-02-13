rule Trojan_Win32_Cosmu_BG_2147827180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cosmu.BG!MTB"
        threat_id = "2147827180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cosmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "glxcodec.exe" wide //weight: 1
        $x_1_2 = "themeuichk.dll" wide //weight: 1
        $x_1_3 = "inject_iebho" wide //weight: 1
        $x_1_4 = "64.18.143.90" wide //weight: 1
        $x_1_5 = "Warning! Virtual machine detected!" wide //weight: 1
        $x_1_6 = "temp\\bot.log" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cosmu_AQ_2147830322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cosmu.AQ!MTB"
        threat_id = "2147830322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cosmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "megalife.besthost.by/bot.zip" ascii //weight: 1
        $x_1_2 = "WINDOWS\\Temp\\sysconf.exe" ascii //weight: 1
        $x_1_3 = "I will sue you!!!11" ascii //weight: 1
        $x_1_4 = "Look what you did to my computer!!!!" ascii //weight: 1
        $x_1_5 = "Susan_lovexx@" ascii //weight: 1
        $x_1_6 = "C:\\log.txt" ascii //weight: 1
        $x_1_7 = "***BELARUS-VIRUS-MAKER***" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cosmu_ARA_2147836265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cosmu.ARA!MTB"
        threat_id = "2147836265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cosmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {bb 00 00 00 00 8a 9a 3f 29 40 00 80 fb 98 75 08 ?? b8 00 00 00 00 ?? ?? 80 fb b0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 0a ?? ?? ?? ?? ?? b8 91 00 00 00 08 c3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c1 e3 03 be 3f 21 40 00 01 de ?? ?? ?? ?? ?? ?? ?? 89 d3 ?? ?? ?? ?? ?? c1 e3 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 3d 04 10 40 00 ?? ?? ?? ?? 01 df b9 08 00 00 00 ?? f3 a4 ?? ?? ?? ?? ?? ?? ?? 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 81 fa a9 54 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0f 85 28 ff ff ff}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cosmu_AN_2147837850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cosmu.AN!MTB"
        threat_id = "2147837850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cosmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3a 50 ff d7 00 5d fb 33 1c 70 00 6c 70 ff 1b d8 00 2a 31 70 ff 1e f7 01 04 e0 fe 3a}  //weight: 1, accuracy: High
        $x_1_2 = {6c 45 78 65 63 75 74 65 45 78 00 00 18 35 40 00 28 35 40 00 00 00 04 00 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cosmu_EM_2147844977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cosmu.EM!MTB"
        threat_id = "2147844977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cosmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Antivirus\\Antivirus\\WormP2P_SelfModify_in_Memory" wide //weight: 1
        $x_1_2 = "VB.Clipboard" ascii //weight: 1
        $x_1_3 = "VB.MDIForm" ascii //weight: 1
        $x_1_4 = "koUdpZrgYPsji" ascii //weight: 1
        $x_1_5 = "bnWcseZrif" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cosmu_AC_2147847640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cosmu.AC!MTB"
        threat_id = "2147847640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cosmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 8d 54 24 3c 50 52 55 ff d3 8d 44 24 1c 8d 4c 24 34 50 68 ?? ?? ?? ?? 51 56 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cosmu_ASB_2147889135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cosmu.ASB!MTB"
        threat_id = "2147889135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cosmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {92 65 76 91 47 4e 02 a5 49 6b 89 f4 8e 56 5b 3b 87 ee 0d a2 37 10 49 68 ec aa a9 2e 8d c5 2d ed fc 8d 2b dd 94 ee 87 4c 8c e4 a2 d8 96 3d ad 27 93 1c ac 97 eb 22 d6 b4 0b ea 6e a1 5d d6 e6 61}  //weight: 1, accuracy: High
        $x_1_2 = {9e 78 06 01 55 3a 83 83 dd 5d f9 73 2a 67 a4 e5 56 95 e9 af 16 1a 29 1d 0f 1d 07 bf 54 a7 72 ec 1a b4 9a e8 07 8f d9 72 ab 53 a9 e5 b5 db 48 e9 33 ca b7 88 a7 fa aa b7 5c c8 d0 b7 45 12 83 84 f0 0e 7e 8b 9c 68 22 39 40 38 40 13 6c 53 69 1d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cosmu_ASC_2147901190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cosmu.ASC!MTB"
        threat_id = "2147901190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cosmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 3c 83 c3 c4 83 55 f0 ff 89 06 57 6a 3c ff 75 f0 53 e8 69 36 00 00 50 5b 8b 46 04 8b ca 99 57 03 d8 13 ca 6a 3c 51}  //weight: 1, accuracy: High
        $x_1_2 = {c9 c3 56 e8 0a 37 00 00 50 5e 09 f6 75 02 5e c3 ff 74 24 08 56 e8 40 fd ff ff f7 d8 1b c0 59 f7 d0 59 23 c6 5e c3 55 54 5d 51 51 8d 45 f8 50 ff 15 8c e0 40 00 8b 45 f8 8b 4d fc 6a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cosmu_MA_2147901641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cosmu.MA!MTB"
        threat_id = "2147901641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cosmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {33 d2 66 89 95 e2 fc ff ff 66 8b 8d dc fc ff ff 33 c0 8d 95 dc fc ff ff 66 85 c9 0f 84}  //weight: 3, accuracy: High
        $x_3_2 = ":\\logbot.txt" ascii //weight: 3
        $x_3_3 = "Bot.exe:" wide //weight: 3
        $x_1_4 = "ejecting" wide //weight: 1
        $x_1_5 = "Monitoring" wide //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" wide //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cosmu_GPX_2147910299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cosmu.GPX!MTB"
        threat_id = "2147910299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cosmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8f 19 1a 23 d1 31 36 d1 55 2b 89 2d 82 c3 64 3b 00 e1 a1 ff 0f 27 db a9 70 5b 1d fd 7d ae 00 c6 44 63 2a 1c f0 53 2a dc 42 ac 04 06 17 34 17 29 ea b2 03 70 f7 3e 4c 9d bc 9e 17 76 05 99 46 3c 2f 5a 17 cf a3 06 c4 28 c7 bb 78 95 32 ac d9 dc 6b 10 82 99 e9 2d ff cd 37 01 a9 d2 74 ab 4f 37 a2 3e 5d ab f6 b1 cd b9 0b 44 30 c5 f7 f7 75 ab}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cosmu_DA_2147913278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cosmu.DA!MTB"
        threat_id = "2147913278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cosmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Get-VSWebFile.ps1" ascii //weight: 20
        $x_1_2 = "e.ps1" ascii //weight: 1
        $x_1_3 = "MicrosoftOutlook2016CAWin32.xml" ascii //weight: 1
        $x_1_4 = "Connections.provxml" ascii //weight: 1
        $x_1_5 = ".files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cosmu_RB_2147913659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cosmu.RB!MTB"
        threat_id = "2147913659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cosmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 44 00 6f 00 73 00 79 00 61 00 20 00 4b 00 6c 00 61 00 73 00 f6 00 72 00 fc 00}  //weight: 1, accuracy: High
        $x_1_2 = {b9 0a 00 00 00 33 c0 8d 7d c8 33 db f3 ab b9 0a 00 00 00 8d 7d 80 f3 ab a1 f0 a4 47 00 89 5d c4 3b c3 89 5d c0 89 5d bc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cosmu_GNE_2147924710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cosmu.GNE!MTB"
        threat_id = "2147924710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cosmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 74 ea 2a 00 db 33 34 3a b1 94 ?? ?? 97 d2 60 13 f2 14 ?? 2a 2e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

