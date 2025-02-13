rule Trojan_Win32_GratefulPos_A_2147729956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GratefulPos.A!MTB"
        threat_id = "2147729956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GratefulPos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {34 30 36 30 33 32 30 33 34 34 33 37 30 35 35 37 3d ?? ?? ?? ?? 32 30 31 30 30 30 30 30 36 38 36 30 30 30 30 30}  //weight: 1, accuracy: Low
        $x_1_2 = "%s.dat" ascii //weight: 1
        $x_1_3 = "\\temp\\Perflib_Perfdata_f44.dat" ascii //weight: 1
        $x_1_4 = "tt2.%s.%s" ascii //weight: 1
        $x_1_5 = "tt1.%s.%s.%s.%s" ascii //weight: 1
        $x_1_6 = "taskmgr.exe" ascii //weight: 1
        $x_1_7 = "explorer.exe" ascii //weight: 1
        $x_1_8 = "mdm.exe" ascii //weight: 1
        $x_1_9 = "sched.exe" ascii //weight: 1
        $x_1_10 = "RegSrvc.exe" ascii //weight: 1
        $x_1_11 = "firefox.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

