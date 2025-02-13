rule Trojan_Win32_Jejmer_A_2147707557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jejmer.A"
        threat_id = "2147707557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jejmer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_SCREENCAPTURE_CAPTURE ( @TEMPDIR & \"/002.jpg\" )" wide //weight: 1
        $x_1_2 = "SHELLEXECUTE ( @TEMPDIR & \"\\DEL.vbs\" )" wide //weight: 1
        $x_1_3 = "TCPSEND ( $SCONECT , @OSLANG & \"|\" & $SSERVERNAME & \"|\" & $SPUERTO & \"|\" & _GETIP" wide //weight: 1
        $x_1_4 = "FILEOPEN ( @STARTUPDIR & \"\\Autorun.vbs\" , 18 )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

