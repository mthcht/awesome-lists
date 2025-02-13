rule Trojan_JS_ObfusHTA_SA_2147933314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:JS/ObfusHTA.SA"
        threat_id = "2147933314"
        type = "Trojan"
        platform = "JS: JavaScript scripts"
        family = "ObfusHTA"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 00 73 00 63 00 72 00 69 00 70 00 74 00 3e 00 65 00 76 00 61 00 6c 00 28 00 [0-32] 2e 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 2f 00 28 00 2e 00 2e 00 29 00 2e 00 2f 00 67 00 2c 00 20 00 66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 28 00 6d 00 61 00 74 00 63 00 68 00 2c 00 20 00 70 00 31 00 29 00 20 00 7b 00 72 00 65 00 74 00 75 00 72 00 6e 00 20 00 53 00 74 00 72 00 69 00 6e 00 67 00 2e 00 66 00 72 00 6f 00 6d 00 43 00 68 00 61 00 72 00 43 00 6f 00 64 00 65 00 28 00 70 00 61 00 72 00 73 00 65 00 49 00 6e 00 74 00 28 00 70 00 31 00 2c 00 20 00 31 00 36 00 29 00 29 00 7d 00 29 00 29 00 3c 00 2f 00 73 00 63 00 72 00 69 00 70 00 74 00 3e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3c 73 63 72 69 70 74 3e 65 76 61 6c 28 [0-32] 2e 72 65 70 6c 61 63 65 28 2f 28 2e 2e 29 2e 2f 67 2c 20 66 75 6e 63 74 69 6f 6e 28 6d 61 74 63 68 2c 20 70 31 29 20 7b 72 65 74 75 72 6e 20 53 74 72 69 6e 67 2e 66 72 6f 6d 43 68 61 72 43 6f 64 65 28 70 61 72 73 65 49 6e 74 28 70 31 2c 20 31 36 29 29 7d 29 29 3c 2f 73 63 72 69 70 74 3e}  //weight: 1, accuracy: Low
        $x_1_3 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

