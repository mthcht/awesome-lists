rule Worm_Win32_Rochap_B_2147651325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rochap.B"
        threat_id = "2147651325"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rochap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Google_Tool_Bar_Notification" ascii //weight: 1
        $x_1_2 = "Resolving hostname %s." ascii //weight: 1
        $x_1_3 = "marakami|102030|" ascii //weight: 1
        $x_1_4 = "Disposition-Notification-To" ascii //weight: 1
        $x_1_5 = "@terra.com.br" ascii //weight: 1
        $x_1_6 = "Linha Atual SMTP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

