rule Trojan_AndroidOS_FakeLook_A_2147666618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeLook.A"
        threat_id = "2147666618"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeLook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(man-in-the-middle attack)!" ascii //weight: 1
        $x_1_2 = "_ackid=" ascii //weight: 1
        $x_1_3 = "SOMETHING NASTY!" ascii //weight: 1
        $x_3_4 = {68 74 74 70 3a 2f 2f 74 68 65 6c 6f 6e 67 69 73 6c 61 6e 64 70 72 65 73 73 2e 63 6f 6d 2f 63 6f 6e 74 72 6f 6c 73 2e 70 68 70 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

