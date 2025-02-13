rule PWS_Win32_Sipay_A_2147623065_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sipay.A"
        threat_id = "2147623065"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sipay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Final RS Stealer\\Project1.vbp" wide //weight: 1
        $x_1_2 = "RS Stealer v" ascii //weight: 1
        $x_3_3 = "RS_Stealer" ascii //weight: 3
        $x_3_4 = "Password  :" ascii //weight: 3
        $x_3_5 = "FTP Server :" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

