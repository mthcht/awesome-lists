rule DoS_Win32_LeopardBlade_A_2147839649_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/LeopardBlade.A!dha"
        threat_id = "2147839649"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "LeopardBlade"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "600"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "%sWindows\\NTDS" ascii //weight: 100
        $x_100_2 = "shadowcopy" ascii //weight: 100
        $x_100_3 = "main.enableDisableProcessPrivilege.func1" ascii //weight: 100
        $x_100_4 = "main.wipe" ascii //weight: 100
        $x_100_5 = "main.Apply.func1" ascii //weight: 100
        $x_100_6 = "main.walkFunc" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

