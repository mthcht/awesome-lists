rule Trojan_Win32_SchoolBoy_GA_2147931393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SchoolBoy.GA!MTB"
        threat_id = "2147931393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SchoolBoy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "cmd /c t1036_test.bat" ascii //weight: 3
        $x_1_2 = "Test_T1036" ascii //weight: 1
        $x_1_3 = "RUNPROGRAM" ascii //weight: 1
        $x_3_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 3
        $x_1_5 = "POSTRUNPROGRAM" ascii //weight: 1
        $x_1_6 = "DelNodeRunDLL32" ascii //weight: 1
        $x_1_7 = "DecryptFileA" ascii //weight: 1
        $x_1_8 = "SHOWWINDOW" ascii //weight: 1
        $x_1_9 = "FINISHMSG" ascii //weight: 1
        $x_1_10 = "msdownld.tmp" ascii //weight: 1
        $x_1_11 = "TMP4351$.TMP" ascii //weight: 1
        $x_1_12 = "SetWindowTextA" ascii //weight: 1
        $x_1_13 = "T1036_~1.BAT" ascii //weight: 1
        $x_1_14 = "Temporary folder" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

