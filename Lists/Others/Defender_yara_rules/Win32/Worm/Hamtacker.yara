rule Worm_Win32_Hamtacker_A_2147610796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Hamtacker.A"
        threat_id = "2147610796"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Hamtacker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "PhoneNumber=" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\WinAFCR" ascii //weight: 1
        $x_1_4 = "Host file loaded ok" ascii //weight: 1
        $x_1_5 = "dialsys.exe" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "POP3 Server" ascii //weight: 1
        $x_1_8 = "SMTP Server" ascii //weight: 1
        $x_1_9 = "this is not a mark, is a cheat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

