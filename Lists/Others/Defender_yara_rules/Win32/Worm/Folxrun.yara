rule Worm_Win32_Folxrun_A_2147694809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Folxrun.A"
        threat_id = "2147694809"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Folxrun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shell\\AutoRun\\command" wide //weight: 1
        $x_1_2 = "start explorer" wide //weight: 1
        $x_1_3 = {00 66 72 6d 5f 6c 6f 63 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = "CaptureScreen" wide //weight: 1
        $x_1_5 = "msfold" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

