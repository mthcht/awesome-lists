rule Trojan_NPM_SuspBunDown_A_2147977302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:NPM/SuspBunDown.A"
        threat_id = "2147977302"
        type = "Trojan"
        platform = "NPM: "
        family = "SuspBunDown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-48] 2d 00 65 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 70 00 6f 00 6c 00 69 00 63 00 79 00 [0-16] 62 00 79 00 70 00 61 00 73 00 73 00}  //weight: 10, accuracy: Low
        $x_10_2 = {65 00 78 00 70 00 61 00 6e 00 64 00 2d 00 61 00 72 00 63 00 68 00 69 00 76 00 65 00 [0-16] 2d 00 6c 00 69 00 74 00 65 00 72 00 61 00 6c 00 70 00 61 00 74 00 68 00 [0-255] 5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 62 00 75 00 6e 00 2d 00 64 00 6c 00 2d 00}  //weight: 10, accuracy: Low
        $x_10_3 = {2d 00 64 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00 02 00 ff 00 5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 62 00 75 00 6e 00 2d 00 64 00 6c 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

