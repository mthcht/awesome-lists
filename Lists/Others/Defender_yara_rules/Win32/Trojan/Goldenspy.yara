rule Trojan_Win32_Goldenspy_A_2147759926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Goldenspy.A!MTB"
        threat_id = "2147759926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Goldenspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\system32\\taxver.exe" ascii //weight: 1
        $x_1_2 = "%s\\debug\\wia\\taxver.exe" ascii //weight: 1
        $x_1_3 = "%s\\temp\\taxver.exe" ascii //weight: 1
        $x_1_4 = "%s\\taxver.exe" ascii //weight: 1
        $x_1_5 = "download.tax-helper.com" ascii //weight: 1
        $x_1_6 = "WMP Assistant Patch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

