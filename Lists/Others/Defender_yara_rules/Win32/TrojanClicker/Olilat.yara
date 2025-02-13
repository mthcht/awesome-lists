rule TrojanClicker_Win32_Olilat_A_2147608186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Olilat.A"
        threat_id = "2147608186"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Olilat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "JOEz\\Bowts\\M-y-L-i-r-a-t\\" wide //weight: 5
        $x_1_2 = "http://adurl.net" wide //weight: 1
        $x_1_3 = "http://mywebresults.info/client124.html" wide //weight: 1
        $x_1_4 = "http://ps.mynaagencies.com/?db=8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

