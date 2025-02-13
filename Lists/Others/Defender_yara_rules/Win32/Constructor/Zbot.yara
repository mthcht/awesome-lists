rule Constructor_Win32_Zbot_A_2147686947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Constructor:Win32/Zbot.A"
        threat_id = "2147686947"
        type = "Constructor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZeuS Builder" ascii //weight: 1
        $x_1_2 = {00 42 41 53 45 43 4f 4e 46 49 47 00}  //weight: 1, accuracy: High
        $x_1_3 = "Global\\%08X%08X%08X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

