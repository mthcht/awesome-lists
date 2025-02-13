rule Trojan_Win32_Tinshel_A_2147730506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinshel.A!bit"
        threat_id = "2147730506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinshel"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 68 a4 00 00 8d ?? ?? ?? 68 0a 00 37 c7 52 e8 ?? ?? ?? ff 68 68 a4 00 00 8d ?? ?? ?? 68 c0 a8 02 1e 50 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "<subsc request code=\"1\">%u</request>" ascii //weight: 1
        $x_1_4 = "%d.%d.%d.%d %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

