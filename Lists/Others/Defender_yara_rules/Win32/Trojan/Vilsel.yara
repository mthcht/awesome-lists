rule Trojan_Win32_Vilsel_A_2147649745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vilsel.A"
        threat_id = "2147649745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vilsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 bc 75 c6 45 bd 73 c6 45 be 65 c6 45 bf 72 c6 45 c0 33 c6 45 c1 32 c6 45 c2 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 c4 61 c6 45 c5 64 c6 45 c6 76 c6 45 c7 61 c6 45 c8 70 c6 45 c9 69 c6 45 ca 33 c6 45 cb 32}  //weight: 1, accuracy: High
        $x_1_3 = {c1 e0 07 8b 4d f8 c1 e9 19 0b c1 89 45 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vilsel_D_2147718577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vilsel.D!bit"
        threat_id = "2147718577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vilsel"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\WINDOWS\\system32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr" wide //weight: 1
        $x_1_3 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools" wide //weight: 1
        $x_1_4 = "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\services\\wscsvc\\Start" wide //weight: 1
        $x_1_5 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" wide //weight: 1
        $x_1_7 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 69 00 6d 00 20 00 53 00 62 00 69 00 65 00 [0-16] 2e 00 65 00 78 00 65 00 20 00 2f 00 66 00}  //weight: 1, accuracy: Low
        $x_1_8 = "net stop SbieSvc" wide //weight: 1
        $x_1_9 = "net stop wscsvc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_Vilsel_CA_2147813295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vilsel.CA!MTB"
        threat_id = "2147813295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vilsel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 fe 10 27 00 00 6a 00 76 1f 8d 4c 24 10 8d 94 24 18 01 00 00 51 68 10 27 00 00 52 57 ff d3 81 ee 10 27 00 00 75 d9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vilsel_AP_2147833422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vilsel.AP!MTB"
        threat_id = "2147833422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vilsel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {84 3a 80 eb 25 c4 88 b8 00 41 90 f3 d7 69 04 a3 45 76 3a 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3}  //weight: 2, accuracy: High
        $x_2_2 = {32 4e 5c 03 b9 93 b1 fd bc 34 93 fc a7 92 38 f1}  //weight: 2, accuracy: High
        $x_1_3 = "This place is not enough for us !" wide //weight: 1
        $x_1_4 = "Rest In Peace... Pesin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vilsel_DAM_2147850087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vilsel.DAM!MTB"
        threat_id = "2147850087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vilsel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {10 2c 0a 35 a3 f7 cc e6 f7 40 ca ed 45 9a ec 8c ad 7b 0a ac cb 3a 4f ad 33 99 66 cf 11 b7}  //weight: 4, accuracy: High
        $x_1_2 = "Sorry i don't want work for you" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vilsel_ABS_2147850828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vilsel.ABS!MTB"
        threat_id = "2147850828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vilsel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*\\AC:\\Documents and Settings\\DucDung\\Desktop\\Pro 3\\Pro3.vbp" wide //weight: 1
        $x_1_2 = "temp.zip" wide //weight: 1
        $x_1_3 = "HideFileExt" wide //weight: 1
        $x_1_4 = "CreateTextFile" wide //weight: 1
        $x_1_5 = "CreateMutexA" ascii //weight: 1
        $x_1_6 = "RegCreateKeyA" ascii //weight: 1
        $x_1_7 = "Project1" ascii //weight: 1
        $x_1_8 = "C:\\WINDOWS\\system32\\msvbvm60.dll\\3" ascii //weight: 1
        $x_10_9 = "music.exe" wide //weight: 10
        $x_10_10 = "musicvn.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vilsel_AMAB_2147852136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vilsel.AMAB!MTB"
        threat_id = "2147852136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vilsel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Documents and Settings\\DucDun" ascii //weight: 1
        $x_1_2 = "HideFileExt" ascii //weight: 1
        $x_1_3 = "CreateTextFile" ascii //weight: 1
        $x_1_4 = "RegCreateKeyA" ascii //weight: 1
        $x_1_5 = "CreateMutexA" ascii //weight: 1
        $x_1_6 = "temp.zip" ascii //weight: 1
        $x_1_7 = "C:\\WINDOWS\\system32\\msvbvm60.dll\\3" ascii //weight: 1
        $x_10_8 = "*\\AD:\\Lap Trinh\\Virus Mau\\Pro 3\\Pro3.vbp" ascii //weight: 10
        $x_10_9 = "*\\AC:\\Documents and Settings\\DucDung\\Desktop\\Pro 3\\Pro3.vbp" ascii //weight: 10
        $x_20_10 = "music.exe" ascii //weight: 20
        $x_20_11 = "musicvn.exe" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 7 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vilsel_EN_2147852399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vilsel.EN!MTB"
        threat_id = "2147852399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vilsel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xtrgkhpvtfntnrxvmscphkg" ascii //weight: 1
        $x_1_2 = "xbcdfg2lmnprstv" ascii //weight: 1
        $x_1_3 = "gethostbyname" ascii //weight: 1
        $x_1_4 = "artupInfo0SyRemD" ascii //weight: 1
        $x_1_5 = "oolhelp32SnapshotRDele" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vilsel_MBXQ_2147918552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vilsel.MBXQ!MTB"
        threat_id = "2147918552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vilsel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 73 40 00 00 f8 32 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 6c 6a 40 00 6c 6a 40 00 5c 11 40 00 78 00 00 00 80 00 00 00 92 00 00 00 93}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vilsel_MBXV_2147924745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vilsel.MBXV!MTB"
        threat_id = "2147924745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vilsel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 6e 08 8b 7e 20 8b 36 38 47 18 75}  //weight: 3, accuracy: High
        $x_2_2 = {20 24 40 00 a8 12 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 00 00 00 00 e9 00 00 00 20 11 40 00 20 11 40 00 e4 10 40 00 78 00 00 00 80 00 00 00 83}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vilsel_RPA_2147931804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vilsel.RPA!MTB"
        threat_id = "2147931804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vilsel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 c0 00 00 00 10 00 00 00 40 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 a0 5b 00 00 00 d0 00 00 00 30 00 00 00 50 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 30 01 00 00 10 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vilsel_RPB_2147931939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vilsel.RPB!MTB"
        threat_id = "2147931939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vilsel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {20 20 20 00 20 20 20 20 00 c0 00 00 00 10 00 00 00 40 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 d0 5b 00 00 00 d0 00 00 00 30 00 00 00 50 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 30 01 00 00 10 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 20 20 20 20 20 20 20 20}  //weight: 10, accuracy: High
        $x_1_2 = "Microsoft Windows" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vilsel_GZZ_2147944852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vilsel.GZZ!MTB"
        threat_id = "2147944852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vilsel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5a 09 1b 28 d1 5d 21 68 2d b7 b7 34 6c 40 c0 0e da 80 ad ?? ?? ?? ?? fe a7 ad e1 ad 2b 03 71}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

