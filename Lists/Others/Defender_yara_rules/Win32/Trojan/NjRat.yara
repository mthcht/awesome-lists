rule Trojan_Win32_NjRat_NEL_2147831125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NjRat.NEL!MTB"
        threat_id = "2147831125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "jmsctls_progress32" wide //weight: 4
        $x_4_2 = "winrarsfxmappingfile.tmp" wide //weight: 4
        $x_3_3 = "mSG5M0llRq" ascii //weight: 3
        $x_3_4 = "nmujuujjiiii2xijijjjjjjmnn" ascii //weight: 3
        $x_3_5 = "_abwwwwowwwwwwwwwwwwwwwwwbap" ascii //weight: 3
        $x_3_6 = "IDC_OWRASKREPLACE" ascii //weight: 3
        $x_1_7 = "sfx\\build" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NjRat_NEAA_2147833195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NjRat.NEAA!MTB"
        threat_id = "2147833195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "P3234SXLQ" wide //weight: 5
        $x_5_2 = "uHOrJtXfDDG" wide //weight: 5
        $x_4_3 = "Hiragana" ascii //weight: 4
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "VkKeyScanA" ascii //weight: 1
        $x_1_6 = "OpenProcess" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "IsWow64Process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NjRat_NEBE_2147838570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NjRat.NEBE!MTB"
        threat_id = "2147838570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Yumi.exe" ascii //weight: 3
        $x_3_2 = "setuper.bat" ascii //weight: 3
        $x_3_3 = "min.vbs" ascii //weight: 3
        $x_2_4 = "Smart Install Maker v. 5.04" ascii //weight: 2
        $x_2_5 = "C:\\TEMP\\$inst\\2. " ascii //weight: 2
        $x_2_6 = "tahoma" ascii //weight: 2
        $x_2_7 = "\\Microsoft\\Internet Explorer\\Quick Launch" ascii //weight: 2
        $x_2_8 = "ProgramW6432Dir" ascii //weight: 2
        $x_2_9 = "msctls_progress32" ascii //weight: 2
        $x_2_10 = "1995-2002 Jean-loup Gailly " ascii //weight: 2
        $x_2_11 = "Software\\Microsoft\\Windows\\CurrentVersion\\GrpConv\\MapGroup" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NjRat_NEDF_2147843184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NjRat.NEDF!MTB"
        threat_id = "2147843184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 e8 18 83 c6 04 88 42 fa 8b c1 c1 e8 10 88 42 fb 8b c1 c1 e8 08 88 42 fc 88 4a fd}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

