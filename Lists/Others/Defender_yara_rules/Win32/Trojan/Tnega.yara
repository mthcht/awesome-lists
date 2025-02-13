rule Trojan_Win32_Tnega_AKV_2147753198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.AKV!MTB"
        threat_id = "2147753198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://cdn.jsd" ascii //weight: 1
        $x_1_2 = "gh/i87924hgHd" ascii //weight: 1
        $x_1_3 = "y/bboxfu<', 'that3.e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_RM_2147759253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.RM!MTB"
        threat_id = "2147759253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 00 03 c6 0f b7 0b 66 81 e1 ff 0f 0f b7 c9 03 c1 01 10}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 04 8b 52 28 8b c6 03 d0 89 15 ?? ?? ?? ?? 6a 00 6a 01 50 ff 15 00 3f 00 90 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_SK_2147761750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.SK!MSR"
        threat_id = "2147761750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "b2eprogramshortname" ascii //weight: 1
        $x_1_2 = "b2eincfile(" ascii //weight: 1
        $x_1_3 = "b2eincfilepath" ascii //weight: 1
        $x_1_4 = "viebobpspa_autologon_admin.bat" ascii //weight: 1
        $x_1_5 = "autologon.exe !viebobpspa EU odeA5SvxTzsDa7kwqDq6K6Xr8Bukha -accepteula" ascii //weight: 1
        $x_1_6 = "net localgroup administrators eu\\!viebobpspa /add" ascii //weight: 1
        $x_1_7 = "C:\\TEMP\\2890.tmp\\viebobpspa_autologon_admin.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Tnega_A_2147765428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.A!MTB"
        threat_id = "2147765428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "cmd.exe /c powershell.exe -windowstyle hidden Sleep 5" ascii //weight: 3
        $x_3_2 = "SendNotifyMessageA" ascii //weight: 3
        $x_3_3 = "GetCommandLineW" ascii //weight: 3
        $x_3_4 = "jbfecargawsbm" ascii //weight: 3
        $x_3_5 = "CreateFileW" ascii //weight: 3
        $x_3_6 = "WriteConsoleW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_TA_2147771282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.TA!MTB"
        threat_id = "2147771282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ge4a3a3hmp2oei7wonjd6" wide //weight: 1
        $x_1_2 = "hfl7sc2bybtrm3vrbetta" wide //weight: 1
        $x_1_3 = "8l6bh3okf117ustby1ewy" wide //weight: 1
        $x_1_4 = "8fl7sc2bybtrm3vrbetta" wide //weight: 1
        $x_1_5 = "fl7sc2bybtrm3vrbetta" wide //weight: 1
        $x_1_6 = "Ofl7sc2bybtrm3vrbetta" wide //weight: 1
        $x_1_7 = "iunek1johwczfq52wub4" wide //weight: 1
        $x_1_8 = "e4a3a3hmp2oei7wonjd6" wide //weight: 1
        $x_1_9 = "cl6bh3okf117ustby1ewy" wide //weight: 1
        $x_1_10 = "pnnxekouten5n025up3x" wide //weight: 1
        $x_1_11 = "l6bh3okf117ustby1ewy" wide //weight: 1
        $x_1_12 = "We4a3a3hmp2oei7wonjd6" wide //weight: 1
        $x_1_13 = "Xfl7sc2bybtrm3vrbetta" wide //weight: 1
        $x_1_14 = "WIOSOSOSOW" wide //weight: 1
        $x_1_15 = "M4rllJQp5V4ozLu19rRwi1FVDrg" ascii //weight: 1
        $x_1_16 = "xHJubNuX0Dne7SrSx" ascii //weight: 1
        $x_1_17 = "3wiDgaUGm86KjJTUnxhbvJrsQVh" ascii //weight: 1
        $x_1_18 = "DgFqNyZD2NcjS7p60JGMch18mc8g" ascii //weight: 1
        $x_1_19 = "Kcwo7VPS7jv1YojyQlx57" ascii //weight: 1
        $x_1_20 = "10ZGr1pWbhrOIVLIHElqUpHlOsqnXD8" ascii //weight: 1
        $x_1_21 = "PJVoIMuQ0v79atX1NViWxq99neINkxs9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_MR_2147771699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.MR!MTB"
        threat_id = "2147771699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WIOSOSOSOW" wide //weight: 10
        $x_1_2 = "RESUTILS.dll" ascii //weight: 1
        $x_1_3 = "RPCRT4.dll" ascii //weight: 1
        $x_1_4 = "wsnmp32.dll" ascii //weight: 1
        $x_1_5 = "_kbhit" ascii //weight: 1
        $x_1_6 = "CONIN$" wide //weight: 1
        $x_1_7 = "ResUtilStopResourceService" ascii //weight: 1
        $x_1_8 = "NdrConformantVaryingArrayMarshall" ascii //weight: 1
        $x_1_9 = "WSALookupServiceBeginW" ascii //weight: 1
        $x_1_10 = "EmptyClipboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tnega_MR_2147771699_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.MR!MTB"
        threat_id = "2147771699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c2 03 c8 0f b6 c1 8b 0d [0-4] 0f b6 84 05 [0-4] 30 04 19 43 3b 9d [0-4] 72 1e 00 0f b6 84 3d [0-4] 88 84 35 [0-4] 88 94 3d [0-4] 0f b6 8c 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_2147772211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.MT!MTB"
        threat_id = "2147772211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 0f b6 ?? 8b [0-5] 0f [0-7] 30 [0-2] 43 3b [0-5] 72 21 00 0f [0-7] 88 [0-6] 88 [0-6] 0f [0-7] 0f b6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_MS_2147772262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.MS!MTB"
        threat_id = "2147772262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "sqlite3.dll" ascii //weight: 1
        $x_1_3 = "\\InProcServer32" wide //weight: 1
        $x_1_4 = "C:\\ProgramData\\Avast Software\\Avast\\aswResp.dat" ascii //weight: 1
        $x_1_5 = "_acmdln" ascii //weight: 1
        $x_1_6 = "_XcptFilter" ascii //weight: 1
        $x_1_7 = "__setusermatherr" ascii //weight: 1
        $x_1_8 = "__p__commode" ascii //weight: 1
        $x_1_9 = "CsrFreeCaptureBuffer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_MU_2147776997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.MU!MTB"
        threat_id = "2147776997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\Avast Software\\Avast\\aswResp.dat" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Borland\\Delphi\\CPM" ascii //weight: 1
        $x_1_3 = "_acmdln" ascii //weight: 1
        $x_1_4 = "_XcptFilter" ascii //weight: 1
        $x_1_5 = "__setusermatherr" ascii //weight: 1
        $x_1_6 = "__p__commode" ascii //weight: 1
        $x_1_7 = "CsrFreeCaptureBuffer" ascii //weight: 1
        $x_1_8 = "sqlite3.dll" ascii //weight: 1
        $x_1_9 = "_except_handler3" ascii //weight: 1
        $x_1_10 = "Dbreak" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_MV_2147776998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.MV!MTB"
        threat_id = "2147776998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sqlite3.dll" ascii //weight: 1
        $x_1_2 = "_except_handler3" ascii //weight: 1
        $x_1_3 = "_XcptFilter" ascii //weight: 1
        $x_1_4 = "_adjust_fdiv" ascii //weight: 1
        $x_1_5 = "__setusermatherr" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Borland\\Delphi\\CPM" ascii //weight: 1
        $x_1_7 = "\\VersionIndependentProgID" ascii //weight: 1
        $x_1_8 = "Dbreak" ascii //weight: 1
        $x_1_9 = "DefenderCSP.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_MW_2147778672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.MW!MTB"
        threat_id = "2147778672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "77"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "AVByteArrayOwner" ascii //weight: 10
        $x_10_2 = "AV_ckLogger" ascii //weight: 10
        $x_10_3 = "bcrypt.dll" ascii //weight: 10
        $x_10_4 = "zeeLog.txt" ascii //weight: 10
        $x_10_5 = "TOOL_BLOCK_ICON" ascii //weight: 10
        $x_10_6 = "Interfaces.ShellExtension.JumpList" ascii //weight: 10
        $x_10_7 = "SOFTWARE\\Borland\\Delphi\\CPM" ascii //weight: 10
        $x_1_8 = "GR_CLASS" ascii //weight: 1
        $x_1_9 = "file.dat" ascii //weight: 1
        $x_1_10 = "base64url" ascii //weight: 1
        $x_1_11 = "regKeyUnlock" ascii //weight: 1
        $x_1_12 = "unlockCode" ascii //weight: 1
        $x_1_13 = "InternetOpenA" ascii //weight: 1
        $x_1_14 = "ImageList_SetOverlayImage" ascii //weight: 1
        $x_1_15 = "CreatePipe" ascii //weight: 1
        $x_1_16 = "DragQueryFileW" ascii //weight: 1
        $x_1_17 = "ShellExecuteW" ascii //weight: 1
        $x_1_18 = "RegisterDragDrop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tnega_QW_2147778829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.QW!MTB"
        threat_id = "2147778829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "opc_package_write" ascii //weight: 3
        $x_5_2 = {4d 65 73 73 61 67 65 42 6f 78 57 00 47 65 74 41 63 74 69 76 65 57 69 6e 64 6f 77 00 47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70}  //weight: 5, accuracy: High
        $x_5_3 = {47 65 74 55 73 65 72 4f 62 6a 65 63 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 57 00 00 00 47 65 74 50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 61 74 69 6f 6e 00 41}  //weight: 5, accuracy: High
        $x_5_4 = {65 2b 30 30 30 00 00 00 31 23 53 4e 41 4e}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_PRF_2147782972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.PRF!MTB"
        threat_id = "2147782972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 5d fc 8b 45 fc 8a 14 38 8b 4d f8 c0 ca 03 32 91 ?? ?? ?? ?? 6a 0c 88 14 38 8d 41 01 99 59 f7 f9 ff 45 fc 89 55 f8 39 75 fc 7c d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_MD_2147787637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.MD!MTB"
        threat_id = "2147787637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 1e 00 88 0a 05 6b 67 1a 45 12 3a 87 ac 17 5a 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_FUV_2147789156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.FUV!MTB"
        threat_id = "2147789156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 83 65 fc 00 8b 35 ?? ?? ?? ?? 8b ce 83 e1 1f 33 35 ?? ?? ?? ?? d3 ce 89 75 ?? c7 45 ?? fe ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {50 c7 44 24 ?? 74 00 70 00 c7 44 24 ?? 73 00 3a 00 c7 44 24 ?? 2f 00 2f 00 c7 44 24 ?? 61 00 2e 00 c7 44 24 ?? 67 00 6f 00 c7 44 24 ?? 61 00 74 00 c7 44 24 ?? 67 00 61 00 c7 44 24 ?? 6d 00 65 00 c7 44 24 ?? 2e 00 63 00 c7 44 24 ?? 6f 00 2f 00 c7 44 24 ?? 75 00 73 00 c7 44 24 ?? 65 00 72 00 c7 44 24 ?? 66 00 2f 00 c7 44 24 ?? 64 00 61 00 c7 44 24 ?? 74 00 2f 00 c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? c7 44 24 ?? 2f 00 73 00 c7 44 24 ?? 71 00 6c 00 c7 44 24 ?? 69 00 74 00 c7 44 24 ?? 65 00 2e 00 c7 44 24 ?? 64 00 61 00 c7 44 24 ?? 74 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_ADJ_2147794586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.ADJ!MTB"
        threat_id = "2147794586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath" ascii //weight: 1
        $x_1_2 = "report_error.php?key=125478824515ADNxu2ccbwe&msg=No-Exes-Found-To-Run" ascii //weight: 1
        $x_1_3 = "http://sornx.xyz" ascii //weight: 1
        $x_1_4 = "myip.php" ascii //weight: 1
        $x_1_5 = "addInstall.php?key=125478824515ADNxu2ccbwe&ip=&oid=12" ascii //weight: 1
        $x_1_6 = "addInstallImpression.php?key=125478824515ADNxu2ccbwe&ip=&oid=12" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_MC_2147795414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.MC!MTB"
        threat_id = "2147795414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 03 43 81 c2 3a 82 84 37 81 c7 de 6b ea e2 39 f3 75 ?? 09 d2 09 d2 c3 26 00 b8 ?? ?? ?? ?? 47 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_MC_2147795414_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.MC!MTB"
        threat_id = "2147795414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hovedkatalog1" wide //weight: 1
        $x_1_2 = "fedtegrever" wide //weight: 1
        $x_1_3 = "Produktudvikle" wide //weight: 1
        $x_1_4 = "Turkom7" ascii //weight: 1
        $x_1_5 = "Binrforms3" ascii //weight: 1
        $x_1_6 = "Surreali" ascii //weight: 1
        $x_1_7 = "Cadave.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_BC_2147797478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.BC!MTB"
        threat_id = "2147797478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 07 d2 c5 36 66 8b 08 85 e7 81 c7 02 00 00 00 f9 66 85 c0 66 f7 c4 55 0f 66 89 0f 66 0f b3 f9 66 c1 e9 83 8d ad fc ff ff ff 0f 9e c5 c1 f1 c1 66 0f ba f1 8a 8b 4c 25 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_MM_2147797777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.MM!MTB"
        threat_id = "2147797777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Top1Mu.Net" ascii //weight: 1
        $x_1_2 = "Data/Logo/System.pro" ascii //weight: 1
        $x_1_3 = "runas" ascii //weight: 1
        $x_1_4 = "Virus Working" ascii //weight: 1
        $x_1_5 = "Release\\Main.pdb" ascii //weight: 1
        $x_1_6 = "_crt_debugger_hook" ascii //weight: 1
        $x_1_7 = "NtResumeProcess" ascii //weight: 1
        $x_1_8 = "OhTTij5lmnomlkjst\\Xuh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_UJK_2147797983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.UJK!MTB"
        threat_id = "2147797983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c2 33 d2 03 c6 f7 f1 8d 0c 3e 46 8a 04 0b 8a 92 ?? ?? ?? ?? 32 c2 88 01 b9 1e 00 00 00 3b 75 f8 72 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_DSAD_2147797984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.DSAD!MTB"
        threat_id = "2147797984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 fb 1a ca d3 d9 66 81 d3 73 12 8b 1c 24 0f c0 ed 0f bf c8 33 5c 24 04}  //weight: 1, accuracy: High
        $x_1_2 = {8b f8 0f a3 c1 33 fb 8b 1c 24 49 33 5c 24 04 49 0f c0 c9 8b cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tnega_C_2147798254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.C!MTB"
        threat_id = "2147798254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f0 8b 4d f4 01 c1 8b 45 f0 8b 55 08 01 c2 8b 45 f0 89 4d ec 8b 4d f8 89 55 e8 99 f7 f9 8b 45 fc 01 d0 8b 4d e8 0f be 09 0f be 10 31 d1 8b 45 ec 88 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_AC_2147798316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.AC!MTB"
        threat_id = "2147798316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0}  //weight: 10, accuracy: High
        $x_3_2 = "cplusplus_me" ascii //weight: 3
        $x_3_3 = "\\payloaddll\\Release\\cmd.pdb" ascii //weight: 3
        $x_3_4 = "etPZKVJV_MenPW" ascii //weight: 3
        $x_3_5 = "ME_ADAudit.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_CC_2147805597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.CC!MTB"
        threat_id = "2147805597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 5e 5e d3 2a f2 d2 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_DBV_2147808920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.DBV!MTB"
        threat_id = "2147808920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 31 00 04 01 0c 00 46 41 4c 44 4c 45 4d 4d 45 4e 45 53 00 04 60 09 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_GMS_2147810962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.GMS!MTB"
        threat_id = "2147810962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 c3 84 fd 30 f9 0f 98 c5 89 c7 c0 c1 02}  //weight: 10, accuracy: High
        $x_1_2 = "MtgKERNEL32.dll" ascii //weight: 1
        $x_1_3 = "DonWS2_32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_CA_2147811072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.CA!MTB"
        threat_id = "2147811072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {39 ff 74 01 ea 31 06 81 c1 [0-4] 2c 81 c1 [0-4] 81 c6 04 00 00 00 81 c2 [0-4] 49 39 fe 75 dc}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_GIS_2147811649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.GIS!MTB"
        threat_id = "2147811649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.Yanjie.com" ascii //weight: 1
        $x_1_2 = "http://101.35.18.254/444.exe" ascii //weight: 1
        $x_1_3 = "fuckyou" ascii //weight: 1
        $x_1_4 = "\\111.exe" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "C:\\ProgramData\\444.exe" ascii //weight: 1
        $x_1_7 = "URLDownloadToFile" ascii //weight: 1
        $x_1_8 = "ShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_GP_2147815053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.GP!MTB"
        threat_id = "2147815053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d8 85 40 00 5b be ?? ?? ?? ?? 21 c6 e8 ?? ?? ?? ?? 50 58 31 1f 47 48 81 c6 ?? ?? ?? ?? 39 cf 75 de}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_QQ_2147815161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.QQ!MTB"
        threat_id = "2147815161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 34 24 83 c4 04 29 c6 e8 ?? ?? ?? ?? 46 31 1a 81 ee ?? ?? ?? ?? 42 56 8b 04 24 83 c4 04 39 ca 75 d7 29 f0 09 c0 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_G_2147815388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.G!MTB"
        threat_id = "2147815388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 17 09 d9 81 c7 ?? ?? ?? ?? 39 c7 75 ed 4e 81 eb ?? ?? ?? ?? c3 09 db 21 c9 00 00 09 c1 43 39 fe 75 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_QR_2147815789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.QR!MTB"
        threat_id = "2147815789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 c2 ea 5a b3 7c 31 03 b9 ?? ?? ?? ?? 01 c9 43 39 f3 75 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_AA_2147816017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.AA!MTB"
        threat_id = "2147816017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 04 24 83 c4 04 81 c0 ?? ?? ?? ?? e8 ?? ?? ?? ?? 31 17 89 c9 47 81 e9 ?? ?? ?? ?? 83 ec 04 89 0c 24 58 39 f7 75 cf}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_AG_2147816459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.AG!MTB"
        threat_id = "2147816459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 ea 01 00 00 00 4a 31 19 4a 81 c6 ?? ?? ?? ?? 41 39 c1 75 da 29 f2 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_XO_2147816563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.XO!MTB"
        threat_id = "2147816563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 3d 24 00 00 e9}  //weight: 1, accuracy: High
        $x_1_2 = {be 3f 10 10 28 e9}  //weight: 1, accuracy: High
        $x_1_3 = {31 34 81 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_F_2147816644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.F!MTB"
        threat_id = "2147816644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 d8 85 40 00 5b 81 e9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 31 1f 47 09 ce 39 d7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_MA_2147818449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.MA!MTB"
        threat_id = "2147818449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UN0lL32" wide //weight: 1
        $x_1_2 = "D$ ShelQP" ascii //weight: 1
        $x_1_3 = "D$,lExe" ascii //weight: 1
        $x_1_4 = "D$0cute" ascii //weight: 1
        $x_1_5 = "UnhandledExceptionFilter" ascii //weight: 1
        $x_1_6 = "VirtualAlloc" ascii //weight: 1
        $x_1_7 = "D$4ExW" ascii //weight: 1
        $x_1_8 = "D$ Clos" ascii //weight: 1
        $x_1_9 = "D$$eHan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_WM_2147818587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.WM!MTB"
        threat_id = "2147818587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 16 81 c6 04 00 00 00 4f 81 e9 ?? ?? ?? ?? 39 c6 75 e8 c3 14 40 00 c3 29 fb 39 db 74 01}  //weight: 10, accuracy: Low
        $x_10_2 = {31 07 09 d1 81 eb ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 39 f7 75 e7 c3 81 c3 f7 23 8e 2b ff 21 f2 39 c3 75 e5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tnega_RK_2147818903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.RK!MTB"
        threat_id = "2147818903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 0b 16 6a 13 0c 12 05 1f 0e 7e ?? ?? ?? 0a 12 03 7c ?? ?? ?? 04 1f 40 20 ?? ?? ?? 08 7e ?? ?? ?? 0a 28 ?? ?? ?? 06 6e 16 6a 3d ?? ?? ?? 00 11 05 28 ?? ?? ?? 06 12 06 7e ?? ?? ?? 0a 7e ?? ?? ?? 0a 12 0a 12 0b 18 11 09 1a 28 ?? ?? ?? 06 6e 72 ?? ?? ?? 70 28 ?? ?? ?? 06 7b ?? ?? ?? 04}  //weight: 1, accuracy: Low
        $x_1_2 = "ZCUVqorSt2LU3dmHhna8VZWumFAA3QPW" ascii //weight: 1
        $x_1_3 = "q</2nK*>De!'7p/V" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_RK_2147818903_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.RK!MTB"
        threat_id = "2147818903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JoinDomain.exe" ascii //weight: 1
        $x_1_2 = "CredUIPromptForCredentials" ascii //weight: 1
        $x_1_3 = "targetName" ascii //weight: 1
        $x_1_4 = "ToUnicode" ascii //weight: 1
        $x_1_5 = "set_UseSystemPasswordChar" ascii //weight: 1
        $x_1_6 = "JGRvbWFpbiA9ICJyZC5nby50aCINCiRwYXNzd29yZCA9ICJyZHBANTV3MHJkIiB8IENvbnZlcnR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_AK_2147818914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.AK!MTB"
        threat_id = "2147818914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 14 53 56 57 89 65 e8 e9}  //weight: 3, accuracy: High
        $x_1_2 = "bmpres.dll" wide //weight: 1
        $x_1_3 = "kLoaderLock" ascii //weight: 1
        $x_1_4 = "LdrUnlockLoaderLock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_AK_2147818914_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.AK!MTB"
        threat_id = "2147818914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\ASProtect\\Key" ascii //weight: 1
        $x_1_2 = "aspr_keys.ini" ascii //weight: 1
        $x_1_3 = "Debugger detected" ascii //weight: 1
        $x_1_4 = "running a debugger!" ascii //weight: 1
        $x_1_5 = "WkBycm9qZ2VxbGloSWZlbVQlKlFdbn5/ZGJgUyMvHRpKIzwnJTN2YXx5cjYnJDYpLkQ2OkBaeHF0c3dta21BVE5Tfww=" ascii //weight: 1
        $x_1_6 = "Please run a virus-check" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_AE_2147819017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.AE!MTB"
        threat_id = "2147819017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d6 81 f6 [0-4] c1 e6 04 81 c6 [0-4] 01 f7 5e 81 c7 [0-4] 81 eb [0-4] 01 fb 81 c3 [0-4] 5f e9}  //weight: 1, accuracy: Low
        $x_1_2 = {89 e7 81 c7 04 00 00 00 81 ef 04 00 00 00 33 3c 24 31 3c 24 33 3c 24 5c 89 2c 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_MB_2147819115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.MB!MTB"
        threat_id = "2147819115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 4c 24 14 8b 44 24 08 56 8b 74 24 10 8a 16 32 d1 88 10 40 46 4f 75}  //weight: 1, accuracy: High
        $x_1_2 = "Sleep" ascii //weight: 1
        $x_1_3 = "CreateProcessA" ascii //weight: 1
        $x_1_4 = "DeleteFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_HM_2147847401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.HM!MTB"
        threat_id = "2147847401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 10 c7 01 00 00 00 00 c6 85 ?? ?? ?? ?? e9 c6 85 [0-37] 55 c6 85 ?? ?? ?? ?? 8b c6 85 ?? ?? ?? ?? ec c6 85 ?? ?? ?? ?? 56 c6 85 ?? ?? ?? ?? 8b c6 85 ?? ?? ?? ?? 75 c6 85 ?? ?? ?? ?? 08 c6 85 ?? ?? ?? ?? ba c6 85 [0-21] c6 85 ?? ?? ?? ?? 00 c6 85 ?? ?? ?? ?? 00 c6 85 ?? ?? ?? ?? 57 c6 85 ?? ?? ?? ?? eb c6 85 ?? ?? ?? ?? 0e c6 85 ?? ?? ?? ?? 8b c6 85 ?? ?? ?? ?? ca c6 85 ?? ?? ?? ?? d1 c6 85 ?? ?? ?? ?? e8 c6 85 ?? ?? ?? ?? c1 c6 85 ?? ?? ?? ?? e1 c6 85 ?? ?? ?? ?? 07 c6 85 ?? ?? ?? ?? 46 c6 85 ?? ?? ?? ?? 0b c6 85 ?? ?? ?? ?? c8 c6 85 ?? ?? ?? ?? 03 c6 85 ?? ?? ?? ?? cf c6 85 ?? ?? ?? ?? 03 c6 85 ?? ?? ?? ?? d1 c6 85 ?? ?? ?? ?? 0f c6 85 ?? ?? ?? ?? be c6 85 ?? ?? ?? ?? 3e}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 68 00 30 00 00 68 00 c2 eb 0b 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tnega_PRG_2147849596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tnega.PRG!MTB"
        threat_id = "2147849596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 55 ec 73 47 8b 45 f4 03 45 f8 8a 08 88 4d ff 8b 55 e0 03 55 e8 8a 02 88 45 fe 0f b6 4d ff c1 f9 03 0f b6 55 ff c1 e2 05 0b ca 0f b6 45 fe 33 c8 8b 55 f4 03 55 f8 88 0a 8b 45 e8 83 c0 01 99 b9 ?? ?? ?? ?? f7 f9 89 55 e8 eb a8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

