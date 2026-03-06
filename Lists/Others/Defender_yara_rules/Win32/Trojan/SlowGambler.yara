rule Trojan_Win32_SlowGambler_D_2147964206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SlowGambler.D!dha"
        threat_id = "2147964206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SlowGambler"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "schtasks.exe" wide //weight: 10
        $x_10_2 = "/create /tn AnimalSoftUpdate\\AnimalSoftUpdater /tr" wide //weight: 10
        $x_10_3 = "/sc once /st" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

