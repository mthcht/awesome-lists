rule Trojan_Win32_DaytonToll_A_2147724723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DaytonToll.A!dha"
        threat_id = "2147724723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DaytonToll"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "182JKWJb1278IUDQ1fnkl289!@_)!@KLWQ*(!@KL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

