rule Trojan_Win32_Altcost_A_2147722748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Altcost.A!bit"
        threat_id = "2147722748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Altcost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://westcost0.altervista.org/w/api2.php?a=" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "ftp://westcost0.altervista.org/w/data/" wide //weight: 1
        $x_1_4 = "//uploadallfiles//" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

