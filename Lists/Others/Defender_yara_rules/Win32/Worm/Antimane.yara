rule Worm_Win32_Antimane_A_2147630813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Antimane.A"
        threat_id = "2147630813"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Antimane"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "<Directory Virtual=\"Download Folder\">" ascii //weight: 10
        $x_10_2 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_1_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 70 72 6f 63 6f 6e 73 75 6c 2e 63 6f 6d 2e 72 6f 2f 66 6c 6f 72 69 6e 2f [0-32] 2e 6d 70 33}  //weight: 1, accuracy: Low
        $x_1_4 = "Adrian Minune" ascii //weight: 1
        $x_1_5 = {31 32 37 2e 30 2e 30 2e 31 [0-16] 77 77 77 2e 6d 61 6e 65 6c 65 34 75 2e 6f 72 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

