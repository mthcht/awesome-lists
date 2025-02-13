rule PWS_Win32_Behz_A_2147605129_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Behz.A"
        threat_id = "2147605129"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Behz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Behzad Ps\\" wide //weight: 3
        $x_1_2 = "RasDialParams!" wide //weight: 1
        $x_1_3 = "\\Init32.exe" wide //weight: 1
        $x_1_4 = "key loger" wide //weight: 1
        $x_1_5 = "khazama.com" wide //weight: 1
        $x_1_6 = "Disable Alt+Crtl+Del" wide //weight: 1
        $x_1_7 = "Send All HTML Pass && ID" wide //weight: 1
        $x_1_8 = "Behzad-PS is Best Password Sender For :" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

