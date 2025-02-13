rule Worm_Win32_Ganub_DR_2147616667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ganub.DR"
        threat_id = "2147616667"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ganub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ShellExecuteA" ascii //weight: 10
        $x_10_2 = "GetTempPathA" ascii //weight: 10
        $x_10_3 = "GetTempFileNameA" ascii //weight: 10
        $x_2_4 = "windir%\\bg1\\Bunga.exe" ascii //weight: 2
        $x_2_5 = "bg1\\dekstop.ini.exe" ascii //weight: 2
        $x_1_6 = "taskkill /f /im Flash.10.exe /im Macromedia.10.exe" ascii //weight: 1
        $x_1_7 = "* Sembahyang " ascii //weight: 1
        $x_1_8 = "MAKE PEACEFUL AND HAPPINESS" ascii //weight: 1
        $x_1_9 = "sory 4 everything" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

