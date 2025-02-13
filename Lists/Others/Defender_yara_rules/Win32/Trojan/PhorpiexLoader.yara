rule Trojan_Win32_PhorpiexLoader_A_2147839987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PhorpiexLoader.A!MTB"
        threat_id = "2147839987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PhorpiexLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sbiedll.dll" wide //weight: 2
        $x_2_2 = "dbghelp.dll" wide //weight: 2
        $x_2_3 = "api_log.dll" wide //weight: 2
        $x_2_4 = "dir_watch.dll" wide //weight: 2
        $x_2_5 = "pstorec.dll" wide //weight: 2
        $x_2_6 = "vmcheck.dll" wide //weight: 2
        $x_2_7 = "wpespy.dll" wide //weight: 2
        $x_2_8 = "connect failed %d" ascii //weight: 2
        $x_2_9 = "connect successfully" ascii //weight: 2
        $x_2_10 = "send failed %d" ascii //weight: 2
        $x_2_11 = "recv failed %d" ascii //weight: 2
        $x_2_12 = "Download sample succeed" ascii //weight: 2
        $x_1_13 = "GetProcAddress" ascii //weight: 1
        $x_1_14 = "LoadLibraryW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

