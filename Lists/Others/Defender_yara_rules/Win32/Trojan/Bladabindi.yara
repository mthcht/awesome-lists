rule Trojan_Win32_Bladabindi_J_2147740903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bladabindi.J!ibt"
        threat_id = "2147740903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keylogger" ascii //weight: 1
        $x_1_2 = "keyStrokesLog" ascii //weight: 1
        $x_1_3 = "victimsOwner" ascii //weight: 1
        $x_1_4 = "/c ping 0 -n 2 & del \"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bladabindi_BA_2147757501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bladabindi.BA!MTB"
        threat_id = "2147757501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TubeHygrostat.dll" ascii //weight: 1
        $x_1_2 = "%%\\rundll32.exe TubeHygrostat,Xerophytes" ascii //weight: 1
        $x_1_3 = "%%\\rundll32.exe Cholecystostomy,Shorelines" ascii //weight: 1
        $x_1_4 = "Cholecystostomy.dll" ascii //weight: 1
        $x_1_5 = "%%\\rundll32.exe Creatinine,Shorelines" ascii //weight: 1
        $x_1_6 = "Creatinine.dll" ascii //weight: 1
        $x_1_7 = "%%\\rundll32.exe Chilblain,Pretor" ascii //weight: 1
        $x_1_8 = "Chilblain.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Bladabindi_JR_2147758299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bladabindi.JR!MTB"
        threat_id = "2147758299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT * FROM Win32_PhysicalMedia" wide //weight: 1
        $x_1_2 = "Win32_ComputerSystem.Name='{0}'" wide //weight: 1
        $x_1_3 = "http://blackl1vesmatter.org/gate" wide //weight: 1
        $x_1_4 = "c:\\windows\\system32\\msinfo32.exe" wide //weight: 1
        $x_1_5 = "http://blackl1vesmatter.org/success" wide //weight: 1
        $x_1_6 = "ExecutionPolicy bypass" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bladabindi_MAK_2147781411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bladabindi.MAK!MTB"
        threat_id = "2147781411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Clipboard changed" wide //weight: 1
        $x_1_2 = {47 00 65 00 74 00 [0-32] 4f 00 70 00 65 00 6e 00 [0-32] 53 00 65 00 6e 00 64 00}  //weight: 1, accuracy: Low
        $x_1_3 = "responseText" wide //weight: 1
        $x_1_4 = "Microsoft\\Windows\\Start Menu\\Programs\\Startup" wide //weight: 1
        $x_1_5 = "https://paste.ee/r/LOhGG" wide //weight: 1
        $x_1_6 = "Microsoft.NET\\Framework\\v4.0.30319\\aspnet_compiler.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bladabindi_BC_2147784163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bladabindi.BC!MTB"
        threat_id = "2147784163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Looker" ascii //weight: 1
        $x_1_2 = "Dagspresse8" ascii //weight: 1
        $x_1_3 = "Labdacismus3" ascii //weight: 1
        $x_1_4 = "Lecanomancer" ascii //weight: 1
        $x_1_5 = "Trsteslsest" ascii //weight: 1
        $x_1_6 = "lensgrevernes" ascii //weight: 1
        $x_1_7 = "Paedagogisk" ascii //weight: 1
        $x_1_8 = "Spunsningerne4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bladabindi_RPL_2147819256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bladabindi.RPL!MTB"
        threat_id = "2147819256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 d2 74 01 ?? 31 32 81 c3 ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 81 c2 04 00 00 00 81 c3 ?? ?? ?? ?? 39 ca 75 dd c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bladabindi_RPT_2147824247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bladabindi.RPT!MTB"
        threat_id = "2147824247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 1e 21 d2 21 d2 81 c6 04 00 00 00 ba ?? ?? ?? ?? 4f 39 ce 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bladabindi_RPU_2147824415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bladabindi.RPU!MTB"
        threat_id = "2147824415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 7d e0 03 4d 08 8a 11 01 c6 03 75 08 ff 4d ec 8a 06 88 16 88 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bladabindi_ARAC_2147847410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bladabindi.ARAC!MTB"
        threat_id = "2147847410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "6P0Ma3IX" ascii //weight: 2
        $x_2_2 = "/:/CQ0JX,FV1Vd2We0Sa4Tc4Q" ascii //weight: 2
        $x_2_3 = ")FU'AQ0MV+HQ'@L" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bladabindi_RPX_2147849726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bladabindi.RPX!MTB"
        threat_id = "2147849726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 04 78 ff 24 03 00 0d 1c 00 04 00 fc c8 1b 05 00 04 72 ff 04 74 ff 05 00 00 24 01 00 0d 14 00 02 00 08 74 ff 0d b8 00 06 00 6b 72 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

