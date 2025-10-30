rule Trojan_Linux_ProcMemDump_B_2147956330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ProcMemDump.B"
        threat_id = "2147956330"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ProcMemDump"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 00 64 00 20 00 69 00 66 00 3d 00 2f 00 70 00 72 00 6f 00 63 00 2f 00 [0-64] 2f 00 6d 00 65 00 6d 00 20 00 6f 00 66 00 3d 00 2f 00 74 00 6d 00 70 00 2f 00 [0-255] 20 00}  //weight: 10, accuracy: Low
        $x_10_2 = {64 00 64 00 20 00 69 00 66 00 3d 00 2f 00 70 00 72 00 6f 00 63 00 2f 00 [0-64] 2f 00 6d 00 65 00 6d 00 20 00 6f 00 66 00 3d 00 2f 00 76 00 61 00 72 00 2f 00 74 00 6d 00 70 00 2f 00 [0-255] 20 00}  //weight: 10, accuracy: Low
        $x_10_3 = {64 00 64 00 20 00 69 00 66 00 3d 00 2f 00 70 00 72 00 6f 00 63 00 2f 00 [0-64] 2f 00 6d 00 65 00 6d 00 20 00 6f 00 66 00 3d 00 2f 00 64 00 65 00 76 00 2f 00 73 00 68 00 6d 00 2f 00 [0-255] 20 00}  //weight: 10, accuracy: Low
        $x_10_4 = {64 00 64 00 20 00 69 00 66 00 3d 00 2f 00 70 00 72 00 6f 00 63 00 2f 00 [0-64] 2f 00 6d 00 65 00 6d 00 20 00 6f 00 66 00 3d 00 2f 00 72 00 6f 00 6f 00 74 00 2f 00 [0-255] 20 00}  //weight: 10, accuracy: Low
        $x_10_5 = {64 00 64 00 20 00 69 00 66 00 3d 00 2f 00 70 00 72 00 6f 00 63 00 2f 00 [0-64] 2f 00 6d 00 65 00 6d 00 20 00 6f 00 66 00 3d 00 2f 00 68 00 6f 00 6d 00 65 00 2f 00 [0-255] 20 00}  //weight: 10, accuracy: Low
        $x_10_6 = {64 00 64 00 20 00 69 00 66 00 3d 00 2f 00 70 00 72 00 6f 00 63 00 2f 00 [0-64] 2f 00 6d 00 65 00 6d 00 20 00 6f 00 66 00 3d 00 2f 00 73 00 72 00 76 00 2f 00 66 00 74 00 70 00 2f 00 [0-255] 20 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

