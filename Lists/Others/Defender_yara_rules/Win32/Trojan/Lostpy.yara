rule Trojan_Win32_Lostpy_A_2147709238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lostpy.A!bit"
        threat_id = "2147709238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lostpy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\system32\\loster.exe" ascii //weight: 1
        $x_1_2 = "software\\microsoft\\windows\\CurrentVersion\\Run\\Terst" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

