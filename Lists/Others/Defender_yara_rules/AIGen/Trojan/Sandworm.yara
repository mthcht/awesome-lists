rule Trojan_AIGen_Sandworm_A_2147968019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AIGen/Sandworm.A"
        threat_id = "2147968019"
        type = "Trojan"
        platform = "AIGen: "
        family = "Sandworm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 63 6c 61 75 64 2d 63 6f 64 65 90}  //weight: 1, accuracy: High
        $x_1_2 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 63 6c 6f 75 64 65 2d 63 6f 64 65 90}  //weight: 1, accuracy: High
        $x_1_3 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 63 6c 6f 75 64 65 90}  //weight: 1, accuracy: High
        $x_1_4 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 63 72 79 70 74 6f 2d 6c 6f 63 61 6c 65 90}  //weight: 1, accuracy: High
        $x_1_5 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 63 72 79 70 74 6f 2d 72 65 61 64 65 72 2d 69 6e 66 6f 90}  //weight: 1, accuracy: High
        $x_1_6 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 64 65 74 65 63 74 2d 63 61 63 68 65 90}  //weight: 1, accuracy: High
        $x_1_7 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 66 6f 72 6d 61 74 2d 64 65 66 61 75 6c 74 73 90}  //weight: 1, accuracy: High
        $x_1_8 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 68 61 72 64 68 74 61 90}  //weight: 1, accuracy: High
        $x_1_9 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 6c 6f 63 61 6c 65 2d 6c 6f 61 64 65 72 2d 70 72 6f 90}  //weight: 1, accuracy: High
        $x_1_10 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 6e 61 6e 69 6f 64 90}  //weight: 1, accuracy: High
        $x_1_11 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 6e 6f 64 65 2d 6e 61 74 69 76 65 2d 62 72 69 64 67 65 90}  //weight: 1, accuracy: High
        $x_1_12 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 6f 70 65 6e 63 72 61 77 90}  //weight: 1, accuracy: High
        $x_1_13 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 70 61 72 73 65 2d 63 6f 6d 70 61 74 90}  //weight: 1, accuracy: High
        $x_1_14 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 72 69 6d 61 72 66 90}  //weight: 1, accuracy: High
        $x_1_15 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 73 63 61 6e 2d 73 74 6f 72 65 90}  //weight: 1, accuracy: High
        $x_1_16 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 73 65 63 70 32 35 36 90}  //weight: 1, accuracy: High
        $x_1_17 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 73 75 70 6f 72 74 2d 63 6f 6c 6f 72 90}  //weight: 1, accuracy: High
        $x_1_18 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 76 65 69 6d 90}  //weight: 1, accuracy: High
        $x_1_19 = {6e 70 6d 90 02 10 69 6e 73 74 61 6c 6c 90 02 10 79 61 72 73 67 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

