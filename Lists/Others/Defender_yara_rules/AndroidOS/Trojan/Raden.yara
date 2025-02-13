rule Trojan_AndroidOS_Raden_A_2147652264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Raden.gen!A"
        threat_id = "2147652264"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Raden"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sendCM" ascii //weight: 1
        $x_1_2 = "mj/utils/MJUtils" ascii //weight: 1
        $x_1_3 = {73 63 44 42 ?? ?? 73 63 4e 75 6d 62 65 72 ?? ?? 73 63 53 74 61 74 65 ?? ?? 73 63 54 61 62 6c 65}  //weight: 1, accuracy: Low
        $x_1_4 = {69 42 6f 6f 6b 4e ?? ?? 69 42 6f 6f 6b 53 ?? ?? 69 42 6f 6f 6b 54}  //weight: 1, accuracy: Low
        $x_1_5 = {6d 49 6e 74 65 76 65 72 ?? ?? 6d 42 75 6e 64 6c 65 ?? ?? 6d 4d 73 67 ?? ?? 6d 4e 75 6d 62 65 72}  //weight: 1, accuracy: Low
        $x_2_6 = "mj/iCalendar/SmsReceiver" ascii //weight: 2
        $x_2_7 = {69 42 6f 6f 6b 54 ?? ?? 73 63 54 61 62 6c 65 ?? ?? 69 42 6f 6f 6b 53 ?? ?? 73 63 53 74 61 74 65 ?? ?? 69 42 6f 6f 6b 4e ?? ?? 73 63 4e 75 6d 62 65 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

