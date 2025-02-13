rule Backdoor_Win32_Truvasys_C_2147718944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Truvasys.C!dha"
        threat_id = "2147718944"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Truvasys"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winxsys.exe" ascii //weight: 1
        $x_1_2 = "resdllx.dll" ascii //weight: 1
        $x_1_3 = "libeay32.dll" ascii //weight: 1
        $x_1_4 = "ssleay32.dll" ascii //weight: 1
        $x_1_5 = "TaskMgr" ascii //weight: 1
        $x_1_6 = "parameters.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

