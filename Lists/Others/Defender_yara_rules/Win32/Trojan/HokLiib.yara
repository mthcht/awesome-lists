rule Trojan_Win32_HokLiib_A_2147939085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HokLiib.A"
        threat_id = "2147939085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HokLiib"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-DontStopIfGoingOnBatteries" wide //weight: 1
        $x_1_2 = "-ExecutionTimeLimit '00:00:00'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

