rule Spammer_Win32_Frotmael_A_2147639542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Frotmael.A"
        threat_id = "2147639542"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Frotmael"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|23lenrek|" wide //weight: 1
        $x_1_2 = "/album/mail.php?u=" wide //weight: 1
        $x_1_3 = "SqUeEzE" ascii //weight: 1
        $x_1_4 = "Email Bomber!" ascii //weight: 1
        $x_1_5 = "Fake Email:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

