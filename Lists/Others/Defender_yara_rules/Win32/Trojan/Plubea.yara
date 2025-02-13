rule Trojan_Win32_Plubea_B_2147733555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plubea.B"
        threat_id = "2147733555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plubea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 4a 0d ce 09 e8}  //weight: 1, accuracy: High
        $x_1_2 = {68 d0 03 5c 09 e8}  //weight: 1, accuracy: High
        $x_1_3 = {68 f4 15 93 b0 e8}  //weight: 1, accuracy: High
        $x_1_4 = {68 31 74 bc 7f e8}  //weight: 1, accuracy: High
        $x_1_5 = {68 b0 06 6a 90 e8}  //weight: 1, accuracy: High
        $x_1_6 = {68 9c b8 ba a6 57 e8}  //weight: 1, accuracy: High
        $x_1_7 = {68 78 5c 3b 55 e8}  //weight: 1, accuracy: High
        $x_1_8 = {68 65 41 fb a7 e8}  //weight: 1, accuracy: High
        $x_1_9 = {6a 40 68 00 30 00 00 8b 46 50 50 8b 46 34 50 ff d7}  //weight: 1, accuracy: High
        $x_1_10 = {25 61 70 70 64 61 74 61 25 5c 46 6c 61 73 68 50 6c 61 79 65 72 00 [0-8] 5c 70 6c 75 67 31 2e 64 61 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

