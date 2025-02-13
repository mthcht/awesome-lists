rule Trojan_AndroidOS_Soft360SMSGrabber_A_2147740457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Soft360SMSGrabber.A"
        threat_id = "2147740457"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Soft360SMSGrabber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {69 42 61 6e 6b 44 42 5f 32 33 2e 64 62 00}  //weight: 3, accuracy: High
        $x_1_2 = {4c 63 6f 6d 2f 73 6f 66 74 33 36 30 2f 69 53 65 72 76 69 63 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 41 6e 64 72 6f 69 64 2f 6f 62 62 2f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

