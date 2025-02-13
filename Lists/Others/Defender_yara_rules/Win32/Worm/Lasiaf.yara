rule Worm_Win32_Lasiaf_B_2147624819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Lasiaf.B"
        threat_id = "2147624819"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Lasiaf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Asmahani\\Asmahani.vbp" wide //weight: 10
        $x_1_2 = "-Lasiaf-" wide //weight: 1
        $x_1_3 = "Asmahani'sMsg.txt" wide //weight: 1
        $x_1_4 = "Myvwa" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

