rule Trojan_Win32_ACRStealer_DA_2147929756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ACRStealer.DA!MTB"
        threat_id = "2147929756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "user_pref(\"extensions.webextensions.uuids" ascii //weight: 1
        $x_1_2 = "<discarded>" ascii //weight: 1
        $x_1_3 = "steamcommunity.com" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "RmRegisterResources" ascii //weight: 1
        $x_1_6 = "InternetWriteFile" ascii //weight: 1
        $x_1_7 = "RstrtMgr.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ACRStealer_AC_2147959347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ACRStealer.AC!MTB"
        threat_id = "2147959347"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b 55 f4 83 c2 01 89 55 f4 8b 45 f4 3b 45 f0 73 12 8b 4d e8 03 4d f4 8b 55 d0 03 55 f4 8a 02 88 01 eb dd}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ACRStealer_AB_2147959576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ACRStealer.AB!MTB"
        threat_id = "2147959576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8a 26 31 c9 41 39 3c 0e 74 13 50 32 24 0e 88 64 15 00 58 41 42 38 c1 76 ec 01 ce eb e3}  //weight: 6, accuracy: High
        $x_1_2 = "rawhide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

