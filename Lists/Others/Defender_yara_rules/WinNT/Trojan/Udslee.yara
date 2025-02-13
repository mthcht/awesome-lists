rule Trojan_WinNT_Udslee_A_2147634498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Udslee.gen!A"
        threat_id = "2147634498"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Udslee"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 64 5b 64 76 5d 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 64 72 76 43 6f 6e 66 69 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {76 62 69 66 75 65 6b 7a 6e 6d 40 67 6a 69 74 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

