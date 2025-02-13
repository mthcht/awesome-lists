rule Backdoor_Win32_Glacid_D_2147657163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Glacid.D"
        threat_id = "2147657163"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Glacid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<DOWNEX>" ascii //weight: 1
        $x_1_2 = "<DOWN>" ascii //weight: 1
        $x_1_3 = "<STOP>" ascii //weight: 1
        $x_1_4 = "<DELAY>" ascii //weight: 1
        $x_1_5 = "Server-Command: " ascii //weight: 1
        $x_1_6 = "net stop %s & sc delete %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

