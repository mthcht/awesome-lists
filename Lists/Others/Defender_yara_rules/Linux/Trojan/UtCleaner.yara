rule Trojan_Linux_UtCleaner_HA_2147836758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/UtCleaner.HA"
        threat_id = "2147836758"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "UtCleaner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 00 63 00 70 00 20 00 [0-32] 20 00 2f 00 76 00 61 00 72 00 2f 00 61 00 64 00 6d 00 2f 00 6c 00 61 00 73 00 74 00 6c 00 6f 00 67 00}  //weight: 2, accuracy: Low
        $x_2_2 = {2f 63 70 20 [0-32] 20 2f 76 61 72 2f 61 64 6d 2f 6c 61 73 74 6c 6f 67}  //weight: 2, accuracy: Low
        $x_2_3 = {2f 00 63 00 70 00 20 00 [0-32] 20 00 2f 00 76 00 61 00 72 00 2f 00 61 00 64 00 6d 00 2f 00 77 00 74 00 6d 00 70 00}  //weight: 2, accuracy: Low
        $x_2_4 = {2f 63 70 20 [0-32] 20 2f 76 61 72 2f 61 64 6d 2f 77 74 6d 70}  //weight: 2, accuracy: Low
        $x_2_5 = {2f 00 63 00 70 00 20 00 [0-32] 20 00 2f 00 76 00 61 00 72 00 2f 00 61 00 64 00 6d 00 2f 00 75 00 74 00 6d 00 70 00}  //weight: 2, accuracy: Low
        $x_2_6 = {2f 63 70 20 [0-32] 20 2f 76 61 72 2f 61 64 6d 2f 75 74 6d 70}  //weight: 2, accuracy: Low
        $x_2_7 = {2f 00 63 00 70 00 20 00 [0-32] 20 00 2f 00 76 00 61 00 72 00 2f 00 6c 00 6f 00 67 00 2f 00 6c 00 61 00 73 00 74 00 6c 00 6f 00 67 00}  //weight: 2, accuracy: Low
        $x_2_8 = {2f 63 70 20 [0-32] 20 2f 76 61 72 2f 6c 6f 67 2f 6c 61 73 74 6c 6f 67}  //weight: 2, accuracy: Low
        $x_2_9 = {2f 00 63 00 70 00 20 00 [0-32] 20 00 2f 00 76 00 61 00 72 00 2f 00 6c 00 6f 00 67 00 2f 00 75 00 74 00 6d 00 70 00}  //weight: 2, accuracy: Low
        $x_2_10 = {2f 63 70 20 [0-32] 20 2f 76 61 72 2f 6c 6f 67 2f 75 74 6d 70}  //weight: 2, accuracy: Low
        $x_2_11 = {2f 00 63 00 70 00 20 00 [0-32] 20 00 2f 00 76 00 61 00 72 00 2f 00 6c 00 6f 00 67 00 2f 00 77 00 74 00 6d 00 70 00}  //weight: 2, accuracy: Low
        $x_2_12 = {2f 63 70 20 [0-32] 20 2f 76 61 72 2f 6c 6f 67 2f 77 74 6d 70}  //weight: 2, accuracy: Low
        $x_2_13 = {2f 00 63 00 70 00 20 00 [0-32] 20 00 2f 00 76 00 61 00 72 00 2f 00 72 00 75 00 6e 00 2f 00 75 00 74 00 6d 00 70 00}  //weight: 2, accuracy: Low
        $x_2_14 = {2f 63 70 20 [0-32] 20 2f 76 61 72 2f 72 75 6e 2f 75 74 6d 70}  //weight: 2, accuracy: Low
        $n_2_15 = {2f 00 63 00 70 00 20 00 2d 00 [0-2] 20 00 2f 00 76 00 61 00 72 00 2f 00 61 00 64 00 6d 00 2f 00 6c 00 61 00 73 00 74 00 6c 00 6f 00 67 00 20 00}  //weight: -2, accuracy: Low
        $n_2_16 = {2f 63 70 20 2d [0-2] 20 2f 76 61 72 2f 61 64 6d 2f 6c 61 73 74 6c 6f 67 20}  //weight: -2, accuracy: Low
        $n_2_17 = {2f 00 63 00 70 00 20 00 2d 00 [0-2] 20 00 2f 00 76 00 61 00 72 00 2f 00 61 00 64 00 6d 00 2f 00 77 00 74 00 6d 00 70 00 20 00}  //weight: -2, accuracy: Low
        $n_2_18 = {2f 63 70 20 2d [0-2] 20 2f 76 61 72 2f 61 64 6d 2f 77 74 6d 70 20}  //weight: -2, accuracy: Low
        $n_2_19 = {2f 00 63 00 70 00 20 00 2d 00 [0-2] 20 00 2f 00 76 00 61 00 72 00 2f 00 61 00 64 00 6d 00 2f 00 75 00 74 00 6d 00 70 00 20 00}  //weight: -2, accuracy: Low
        $n_2_20 = {2f 63 70 20 2d [0-2] 20 2f 76 61 72 2f 61 64 6d 2f 75 74 6d 70 20}  //weight: -2, accuracy: Low
        $n_2_21 = {2f 00 63 00 70 00 20 00 2d 00 [0-2] 20 00 2f 00 76 00 61 00 72 00 2f 00 61 00 64 00 6d 00 2f 00 77 00 74 00 6d 00 70 00 78 00 20 00}  //weight: -2, accuracy: Low
        $n_2_22 = {2f 63 70 20 2d [0-2] 20 2f 76 61 72 2f 61 64 6d 2f 77 74 6d 70 78 20}  //weight: -2, accuracy: Low
        $n_2_23 = {2f 00 63 00 70 00 20 00 2d 00 [0-2] 20 00 2f 00 76 00 61 00 72 00 2f 00 61 00 64 00 6d 00 2f 00 75 00 74 00 6d 00 70 00 78 00 20 00}  //weight: -2, accuracy: Low
        $n_2_24 = {2f 63 70 20 2d [0-2] 20 2f 76 61 72 2f 61 64 6d 2f 75 74 6d 70 78 20}  //weight: -2, accuracy: Low
        $n_2_25 = {2f 00 63 00 70 00 20 00 2d 00 [0-2] 20 00 2f 00 76 00 61 00 72 00 2f 00 6c 00 6f 00 67 00 2f 00 6c 00 61 00 73 00 74 00 6c 00 6f 00 67 00 20 00}  //weight: -2, accuracy: Low
        $n_2_26 = {2f 63 70 20 2d [0-2] 20 2f 76 61 72 2f 6c 6f 67 2f 6c 61 73 74 6c 6f 67 20}  //weight: -2, accuracy: Low
        $n_2_27 = {2f 00 63 00 70 00 20 00 2d 00 [0-2] 20 00 2f 00 76 00 61 00 72 00 2f 00 6c 00 6f 00 67 00 2f 00 75 00 74 00 6d 00 70 00 20 00}  //weight: -2, accuracy: Low
        $n_2_28 = {2f 63 70 20 2d [0-2] 20 2f 76 61 72 2f 6c 6f 67 2f 75 74 6d 70 20}  //weight: -2, accuracy: Low
        $n_2_29 = {2f 00 63 00 70 00 20 00 2d 00 [0-2] 20 00 2f 00 76 00 61 00 72 00 2f 00 6c 00 6f 00 67 00 2f 00 77 00 74 00 6d 00 70 00 20 00}  //weight: -2, accuracy: Low
        $n_2_30 = {2f 63 70 20 2d [0-2] 20 2f 76 61 72 2f 6c 6f 67 2f 77 74 6d 70 20}  //weight: -2, accuracy: Low
        $n_2_31 = {2f 00 63 00 70 00 20 00 2d 00 [0-2] 20 00 2f 00 76 00 61 00 72 00 2f 00 72 00 75 00 6e 00 2f 00 75 00 74 00 6d 00 70 00 20 00}  //weight: -2, accuracy: Low
        $n_2_32 = {2f 63 70 20 2d [0-2] 20 2f 76 61 72 2f 72 75 6e 2f 75 74 6d 70 20}  //weight: -2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

