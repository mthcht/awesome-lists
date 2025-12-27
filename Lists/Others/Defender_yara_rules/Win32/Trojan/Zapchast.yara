rule Trojan_Win32_Zapchast_B_2147799408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zapchast.B!MTB"
        threat_id = "2147799408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 54 24 1b 88 54 24 15 0f be 44 24 15 85 c0 75 10 8b 8c 24 e4 00 00 00 89 8c 24 48 01 00 00 eb 1c 0f be 44 24 15 33 84 24 e4 00 00 00 ba 93 01 00 01 f7 e2 89 84 24 e4 00 00 00 eb a5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zapchast_MB_2147807608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zapchast.MB!MTB"
        threat_id = "2147807608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 83 c4 0c 8b 55 ec 8b 4d e8 66 89 0c 02 33 c9 66 89 4c 02 02 8d 14 5d ?? ?? ?? ?? 8b cf e8 ?? ?? ?? ?? 8b 45 f0 89 06 eb ?? 57 56 50 e8 ?? ?? ?? ?? 8b 45 f0 8d 55 f0 8b 4d e8 83 c4 0c 66 89 0c 07 33 c9 66 89 4c 07 02 8b ce e8 ?? ?? ?? ?? 8b 45 08 40 89 45 08 3b 45 0c 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = ".debug_weaknames" ascii //weight: 1
        $x_1_3 = ".debug_pubnames" ascii //weight: 1
        $x_1_4 = "Sleep" ascii //weight: 1
        $x_1_5 = "proxies.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zapchast_DE_2147808202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zapchast.DE!MTB"
        threat_id = "2147808202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/mixone" ascii //weight: 3
        $x_3_2 = "powershell -inputformat none -outputformat none -NonInteractive -Command" ascii //weight: 3
        $x_3_3 = "DisableRealtimeMonitoring" ascii //weight: 3
        $x_3_4 = "ExclusionPath" ascii //weight: 3
        $x_3_5 = "ZN6curlpp10OptionBaseC2E10CURLoption" ascii //weight: 3
        $x_3_6 = "curl_easy_setopt" ascii //weight: 3
        $x_3_7 = "report_error.php?key=125478824515ADNxu2ccbwe" ascii //weight: 3
        $x_3_8 = "No-Exes-Found-To-Run" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Zapchast_RF_2147812767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zapchast.RF!MTB"
        threat_id = "2147812767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e4 f8 83 ec 24 8b 45 ?? 8b 4d ?? 83 f0 ?? 89 44 24 ?? 83 f1 00 89 4c 24 ?? c7 44 24 ?? 17 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zapchast_AH_2147816465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zapchast.AH!MTB"
        threat_id = "2147816465"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 e0 1f 6a 20 59 2b c8 8b 45 08 d3 c8}  //weight: 5, accuracy: High
        $x_5_2 = "XYZX|ZTXT|XYZX|ZTXT|XYZX|ZTXT|XYZX|ZTXT|XYZX" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zapchast_ABS_2147849339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zapchast.ABS!MTB"
        threat_id = "2147849339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 2c 11 07 6f ?? 00 00 0a 74 ?? 00 00 01 0d 09 6f ?? 00 00 0a 2c 17 09 6f ?? 00 00 0a 17 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 11 07 6f ?? 00 00 0a 2d cb}  //weight: 10, accuracy: Low
        $x_10_2 = {07 8e 69 1b 59 8d ?? 00 00 01 13 04 07 1b 11 04 16 07 8e 69 1b 59 28 ?? 00 00 0a 11 04}  //weight: 10, accuracy: Low
        $x_1_3 = "GetFolderPath" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zapchast_RG_2147891804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zapchast.RG!MTB"
        threat_id = "2147891804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mexwategehuwowihnogmere.dll" ascii //weight: 1
        $x_1_2 = "Meslohmogux.dll" ascii //weight: 1
        $x_1_3 = "Lexusujezu.dll" ascii //weight: 1
        $x_1_4 = "Zagejimojojoxiho.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zapchast_GA_2147896251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zapchast.GA!MTB"
        threat_id = "2147896251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {89 86 d0 00 00 00 89 7c 24 10 e8 7f 11 00 00 89 44 24 14 8b 44 24 20 2b c3 99 33 c2 2b c2 89 44 24 0c db 44 24 0c dc 0d ?? ?? ?? ?? e8 5d 11 00 00 db 44 24 2c db 44 24 10 89 44 24 0c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zapchast_AB_2147896945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zapchast.AB!MTB"
        threat_id = "2147896945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 d2 8b c1 f7 b5 f8 fe ff ff 0f b6 9c 0d fc fe ff ff 41 0f b6 14 3a 03 d3 03 f2 81 e6 ff 00 00 00 8a 84 35 fc fe ff ff 88 84 0d fb fe ff ff 88 9c 35 fc fe ff ff 81 f9 00 01 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zapchast_GZZ_2147905377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zapchast.GZZ!MTB"
        threat_id = "2147905377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "8,838E8d8v" ascii //weight: 5
        $x_5_2 = {10 3f 20 3f 32 3f 3a 3f 46 3f 58 3f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zapchast_MK_2147957516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zapchast.MK!MTB"
        threat_id = "2147957516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "cmd.exe /C powershell -ExecutionPolicy Bypass -File" ascii //weight: 20
        $x_15_2 = "cmd.exe /C powershell -Command \"Set-ExecutionPolicy Unrestricted -Scope CurrentUser\"" ascii //weight: 15
        $x_10_3 = "Register-ScheduledTask -Xml $xmlContent -TaskName $taskName" ascii //weight: 10
        $x_5_4 = "Application Data\\updated.ps1" ascii //weight: 5
        $x_3_5 = "Application Data\\PolicyManagement.xml" ascii //weight: 3
        $x_2_6 = "CiAgPC9TZXR0aW5ncz4KICA8QWN0aW9ucyBDb250ZXh0PSJBbGxVc2VycyI+CiAgICA8RXhlYz4KICAgICAgPENvbW1hbmQ+5paH5Lu257ud5a+56Lev5b6EPC9Db21tYW5kPgogICAgPC9FeGVjPgogIDwvQWN0aW9ucz4KPC9UYXNrPg==" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

