rule Worm_Win32_Gotix_B_2147583563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gotix.B"
        threat_id = "2147583563"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gotix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Virus\\Grogotix\\Grogotix.vbp" wide //weight: 1
        $x_1_2 = "C:\\Program Files\\Norman" wide //weight: 1
        $x_1_3 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

