rule Trojan_WinNT_Swamiss_A_2147641406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Swamiss.A"
        threat_id = "2147641406"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Swamiss"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 53 00 79 00 73 00 4d 00 6f 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 01 6a 1a 3c 61 5f 0f be c0 7c 0b 83 e8 4a 99 f7 ff 80 c2 61 eb 09 83 e8 2a 99 f7 ff 80 c2 41 88 11 41 80 39 00 75 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

