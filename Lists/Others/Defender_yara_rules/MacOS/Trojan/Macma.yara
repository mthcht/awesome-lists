rule Trojan_MacOS_Macma_B_2147799121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Macma.B"
        threat_id = "2147799121"
        type = "Trojan"
        platform = "MacOS: "
        family = "Macma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "com.ccc.keyboardrecord" ascii //weight: 2
        $x_1_2 = "useage %s path useragentpid" ascii //weight: 1
        $x_1_3 = {63 6f 6d 2e 63 63 63 2e 77 72 69 74 65 5f 71 75 65 75 65 00 66 69 6c 65 20 69 73 20 00 25 59 2d 25 6d 2d 25 64 20 25 48 3a 25 4d 3a 25 53 00 77 00 70 73 20 2d 70 20 25 73 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c}  //weight: 1, accuracy: High
        $x_1_4 = {41 5e 5d c3 4c 8d ?? ?? ?? ff ff bf 01 00 00 00 31 f6 31 d2 b9 00 0c 00 00 49 89 d9 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

