rule Worm_Win32_Kozy_A_2147652966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kozy.A"
        threat_id = "2147652966"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kozy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "control.ozy" wide //weight: 1
        $x_1_2 = "smtp.gmail." wide //weight: 1
        $x_1_3 = "open=autorun.exe" ascii //weight: 1
        $x_1_4 = "[autorun]" ascii //weight: 1
        $x_1_5 = "winmgmts:\\\\.\\root\\SecurityCenter" wide //weight: 1
        $x_1_6 = "del c:\\\\windows\\\\system32\\\\kernel32.dll" ascii //weight: 1
        $x_1_7 = "[Delete]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

