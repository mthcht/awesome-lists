rule Trojan_WinNT_QHosts_B_2147654491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/QHosts.B"
        threat_id = "2147654491"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 80 0f 05 fd 50 8d 45 d8 50 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {6f 70 65 72 61 2e 65 78 65 00 [0-16] 66 69 72 65 66 6f 78 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 6f 73 74 37 00 [0-8] 68 73 74 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

