rule PWS_Win32_Browsrpod_PAA_2147775933_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Browsrpod.PAA!MTB"
        threat_id = "2147775933"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Browsrpod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "authentication tag mismatch" wide //weight: 10
        $x_10_2 = "password_value" wide //weight: 10
        $x_10_3 = "Passwords.txt" wide //weight: 10
        $x_10_4 = "\\Login Data" wide //weight: 10
        $x_10_5 = "Tokens.txt" wide //weight: 10
        $x_10_6 = "Info.txt" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

