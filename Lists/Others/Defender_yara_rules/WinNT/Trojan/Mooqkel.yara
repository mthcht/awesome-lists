rule Trojan_WinNT_Mooqkel_A_2147697076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Mooqkel.A"
        threat_id = "2147697076"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Mooqkel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 4f 53 54 [0-5] 47 45 54 [0-5] 48 54 54 50 2f 31 2e 31 20 34 30 34}  //weight: 1, accuracy: Low
        $x_1_2 = {42 41 53 45 [0-16] 61 63 74 69 6f 6e [0-5] 69 74 65 6d}  //weight: 1, accuracy: Low
        $x_1_3 = "HTTP/1.1 302 Found" ascii //weight: 1
        $x_1_4 = "\\Device\\M2Tdi" wide //weight: 1
        $x_1_5 = {b9 4e e6 40 bb}  //weight: 1, accuracy: High
        $x_1_6 = {0a 46 42 8a 0e 84 c9 75 ee 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

