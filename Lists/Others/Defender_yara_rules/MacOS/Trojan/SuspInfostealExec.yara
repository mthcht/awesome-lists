rule Trojan_MacOS_SuspInfostealExec_C_2147961781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspInfostealExec.C"
        threat_id = "2147961781"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspInfostealExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-6] 6c 00 73 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-6] 70 00 73 00 20 00 61 00 75 00 78 00 20 00 2d 00 6f 00 20 00 63 00 6f 00 6d 00 6d 00 20 00 7c 00 20 00 67 00 72 00 65 00 70 00 20 00 63 00 6f 00 6d 00 2e 00 61 00 70 00 70 00 6c 00 65 00 2e 00 63 00 6c 00 69 00}  //weight: 1, accuracy: Low
        $x_1_3 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-6] 6e 00 6f 00 68 00 75 00 70 00 20 00 63 00 75 00 72 00 6c 00 20 00 2d 00 58 00 20 00 50 00 4f 00 53 00 54 00 20 00 2d 00 6b 00 20 00 2d 00 48 00 20 00}  //weight: 1, accuracy: Low
        $x_1_4 = "Library/Application Support/Telegram Desktop/tdata/" wide //weight: 1
        $x_1_5 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-6] 74 00 65 00 73 00 74 00 20 00 2d 00}  //weight: 1, accuracy: Low
        $x_1_6 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-6] 72 00 6d 00 20 00 2d 00 72 00 66 00}  //weight: 1, accuracy: Low
        $x_1_7 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-6] 6d 00 6b 00 64 00 69 00 72 00 20 00 2d 00 70 00}  //weight: 1, accuracy: Low
        $x_1_8 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-6] 66 00 69 00 6e 00 64 00}  //weight: 1, accuracy: Low
        $x_1_9 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-6] 62 00 61 00 73 00 65 00 6e 00 61 00 6d 00 65 00 20 00}  //weight: 1, accuracy: Low
        $x_1_10 = {64 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-6] 63 00 70 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

