rule Worm_Win32_Sersam_A_2147659858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sersam.A"
        threat_id = "2147659858"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sersam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\ServiceSample.vbp" wide //weight: 1
        $x_1_2 = "munE\\ksiD\\secivreS\\100teSlortnoC\\METSYS" wide //weight: 1
        $x_1_3 = "route print >>" wide //weight: 1
        $x_1_4 = "onl.php" wide //weight: 1
        $x_1_5 = "USBKey.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

