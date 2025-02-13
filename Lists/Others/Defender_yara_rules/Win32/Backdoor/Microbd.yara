rule Backdoor_Win32_Microbd_D_2147814326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Microbd.D!dha"
        threat_id = "2147814326"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Microbd"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s|%s|%d|%s|%d|%d" wide //weight: 1
        $x_1_2 = "chcp 65001 > NUL" wide //weight: 1
        $x_1_3 = "cmd.exe /C \"%s%s" wide //weight: 1
        $x_1_4 = "uninst" ascii //weight: 1
        $x_1_5 = "shell" ascii //weight: 1
        $x_1_6 = "flist" ascii //weight: 1
        $x_1_7 = "screenshot" ascii //weight: 1
        $x_5_8 = "30D78F9B-C56E-472C-8A29-E9F27FD8C985" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

