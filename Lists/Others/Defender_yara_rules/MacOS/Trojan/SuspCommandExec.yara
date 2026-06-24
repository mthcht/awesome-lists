rule Trojan_MacOS_SuspCommandExec_A_2147972275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspCommandExec.A"
        threat_id = "2147972275"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspCommandExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "(mktemp /tmp/s.XXXXXX)&&mv" wide //weight: 1
        $x_1_2 = {2e 00 64 00 6d 00 67 00 [0-6] 26 00 26 00 63 00 75 00 72 00 6c 00 20 00 2d 00 66 00 73 00 53 00 4c 00 20 00 [0-6] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = ".beer/" wide //weight: 1
        $x_1_4 = "/Volumes" wide //weight: 1
        $x_1_5 = {28 00 68 00 64 00 69 00 75 00 74 00 69 00 6c 00 20 00 61 00 74 00 74 00 61 00 63 00 68 00 20 00 2d 00 6e 00 6f 00 62 00 72 00 6f 00 77 00 73 00 65 00 20 00 [0-32] 20 00 32 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 [0-8] 61 00 77 00 6b 00 20 00 2d 00 46 00}  //weight: 1, accuracy: Low
        $x_1_6 = {68 00 65 00 61 00 64 00 20 00 2d 00 31 00 29 00 26 00 26 00 [0-16] 28 00 66 00 69 00 6e 00 64 00 [0-32] 2d 00 6d 00 61 00 78 00 64 00 65 00 70 00 74 00 68 00}  //weight: 1, accuracy: Low
        $x_1_7 = {2d 00 6e 00 61 00 6d 00 65 00 20 00 [0-4] 2a 00 2e 00 61 00 70 00 70 00 [0-4] 20 00 2d 00 6f 00 20 00 2d 00 6e 00 61 00 6d 00 65 00 20 00 [0-2] 2a 00 2e 00 70 00 6b 00 67 00}  //weight: 1, accuracy: Low
        $x_1_8 = {68 00 65 00 61 00 64 00 20 00 2d 00 31 00 29 00 26 00 26 00 5b 00 20 00 2d 00 6e 00 20 00 [0-16] 5d 00 26 00 26 00 6f 00 70 00 65 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

