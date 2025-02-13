rule PWS_Win32_Facepass_B_2147670829_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Facepass.B"
        threat_id = "2147670829"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Facepass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "c:\\temp\\bot.log" wide //weight: 10
        $x_10_2 = "inject_firefox" wide //weight: 10
        $x_10_3 = "inject_iebho" wide //weight: 10
        $x_10_4 = "inject_regrun" wide //weight: 10
        $x_10_5 = "inject_winlogon" wide //weight: 10
        $x_1_6 = "facebook.com/login.php" wide //weight: 1
        $x_1_7 = "google.com/accounts/Login" wide //weight: 1
        $x_1_8 = "mail.ru/cgi-bin/login" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

