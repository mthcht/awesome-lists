rule Trojan_WinNT_DCPter_A_2147649491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/DCPter.gen!A"
        threat_id = "2147649491"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "DCPter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 43 53 49 20 6d 69 6e 69 70 6f 72 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 65 6c 61 79 00 00 00 64 65 6e 69 65 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {3d 3f 25 73 3f 42 3f 00 48 36 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

