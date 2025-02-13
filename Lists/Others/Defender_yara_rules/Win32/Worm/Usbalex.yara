rule Worm_Win32_Usbalex_B_2147597962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Usbalex.B"
        threat_id = "2147597962"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Usbalex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "SVCH0ST.EXE" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "recycled\\desktop.ini" ascii //weight: 1
        $x_1_5 = "Policies\\Comdlg32" ascii //weight: 1
        $x_1_6 = "Policies\\Network" ascii //weight: 1
        $x_1_7 = "Policies\\Explorer" ascii //weight: 1
        $x_1_8 = "usb Version 1.0" wide //weight: 1
        $x_1_9 = "usb.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

