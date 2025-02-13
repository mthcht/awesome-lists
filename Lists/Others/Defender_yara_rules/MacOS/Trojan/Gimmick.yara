rule Trojan_MacOS_Gimmick_A_2147815702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Gimmick.A"
        threat_id = "2147815702"
        type = "Trojan"
        platform = "MacOS: "
        family = "Gimmick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 2f 75 2f 25 40 00 2e 25 40 2e 25 40 00 62 61 73 65 5f 6a 73 6f 6e 00 64 6f 77 6e 5f 6a 73 6f 6e 00 75 70 6c 6f 61 64 5f 6a 73 6f 6e 00 74 65 72 6d 69 6e 5f 6a 73 6f 6e 00 72 65 71 75 65 73 74 5f 6a 73 6f 6e 00 6f 6e 6c 69 6e 65 5f 6a 73}  //weight: 1, accuracy: High
        $x_1_2 = {56 5f 69 73 44 6f 77 6e 00 2f 55 73 65 72 73 00 2e 2e 00 77 68 6f 00 20 63 6f 6e 73 6f 6c 65 20 00 75 73 65 72 3a 20 25 73 20 6e 6f 74 20 61 20 72 65 61 6c 20 75 73 65 72 0a 00 2f 76 61 72 2f 72 6f 6f 74 2f 4c 69 62 72 61 72 79 2f 50 72 65 66 65 72 65 6e 63 65 73 2f 43 6f 72 65 6c 44 52 41 57 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

