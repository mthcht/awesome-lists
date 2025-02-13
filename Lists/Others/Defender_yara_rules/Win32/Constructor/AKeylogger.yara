rule Constructor_Win32_AKeylogger_A_2147629109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Constructor:Win32/AKeylogger.A"
        threat_id = "2147629109"
        type = "Constructor"
        platform = "Win32: Windows 32-bit platform"
        family = "AKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Albertino Keylogger Creator" ascii //weight: 1
        $x_1_2 = "please make sure your FTP settings are correct!!!" wide //weight: 1
        $x_1_3 = "?cmd=_s-xclick&hosted_button_id=1536236" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

