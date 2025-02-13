rule Trojan_MacOS_Dropper_A_2147818487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Dropper.A"
        threat_id = "2147818487"
        type = "Trojan"
        platform = "MacOS: "
        family = "Dropper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Golden Book1" ascii //weight: 1
        $x_1_2 = "H5YL5668C71" ascii //weight: 1
        $x_2_3 = {46 69 6e 64 65 72 46 6f 6e 74 73 55 70 64 61 74 65 72 2e 61 70 70 27 00 6b 69 6c 6c 61 6c 6c 20 54 65 72 6d 69 6e 61 6c}  //weight: 2, accuracy: High
        $x_2_4 = {3c 73 74 72 69 6e 67 3e 69 54 75 6e 65 73 5f 74 72 75 73 68 3c 2f 73 74 72 69 6e 67 3e 0d 0a 09 3c 6b 65 79 3e 4f 6e 44 65 6d 61 6e 64 3c 2f 6b 65 79 3e}  //weight: 2, accuracy: High
        $x_1_5 = "pgrep -f safarifontsagent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

