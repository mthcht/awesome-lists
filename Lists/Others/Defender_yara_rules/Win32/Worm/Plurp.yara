rule Worm_Win32_Plurp_A_2147611103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Plurp.A"
        threat_id = "2147611103"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Plurp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "63"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CreateMutexA" ascii //weight: 10
        $x_10_2 = "MapViewOfFile" ascii //weight: 10
        $x_10_3 = "GetSystemDirectoryA" ascii //weight: 10
        $x_10_4 = "WNetEnumResourceA" ascii //weight: 10
        $x_10_5 = "EnumProcessModules" ascii //weight: 10
        $x_10_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_1_7 = "Content-Type: application/octet-stream; file=PurpleMood.scr" ascii //weight: 1
        $x_1_8 = "Content-Disposition: attachment; filename=PurpleMood.scr" ascii //weight: 1
        $x_1_9 = "C:\\WINDOWS\\system32\\PurpleMood.scr" ascii //weight: 1
        $x_1_10 = "\\PurpleMood.scr" ascii //weight: 1
        $x_1_11 = "pact518.hit.edu.cn" ascii //weight: 1
        $x_1_12 = "HELO cx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

