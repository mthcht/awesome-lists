rule Trojan_WinCE_Sejweek_A_2147630328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinCE/Sejweek.A"
        threat_id = "2147630328"
        type = "Trojan"
        platform = "WinCE: Windows CE platform"
        family = "Sejweek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://today-friday.cn/maran/sejvan/get.php" wide //weight: 1
        $x_1_2 = {72 e5 00 00 70 80 0a 00 00 04 20 80 6d ef 04 80 0b 00 00 04 20 80 6d ef 04 80 0c 00 00 04 17 80 10 00 00 04 73 58 00 00 0a 80 12 00 00 04 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinCE_Sejweek_B_2147630522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinCE/Sejweek.B"
        threat_id = "2147630522"
        type = "Trojan"
        platform = "WinCE: Windows CE platform"
        family = "Sejweek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 75 00 6e 00 69 00 71 00 75 00 65 00 2d 00 63 00 61 00 73 00 68 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 6c 00 61 00 72 00 6d 00 2f 00 67 00 65 00 74 00 2e 00 70 00 68 00 70 00 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 73 03 00 70 80 15 00 00 04 20 80 6d ef 04 80 16 00 00 04 20 80 6d ef 04 80 17 00 00 04 17 80 1b 00 00 04 73 e5 00 00 0a 80 1d 00 00 04 20 6c 07 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

