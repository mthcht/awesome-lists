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

