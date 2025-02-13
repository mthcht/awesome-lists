rule Trojan_MacOS_Bezdez_A_2147741667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Bezdez.A"
        threat_id = "2147741667"
        type = "Trojan"
        platform = "MacOS: "
        family = "Bezdez"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff cb 45 0f b6 27 [0-7] 89 d9 44 29 e1 31 c1 41 89 df 45 29 e7 89 8d 48 ff ff ff 0f 84 9a 00 00 00 48 8d bd}  //weight: 2, accuracy: Low
        $x_1_2 = "Starting snake in event-driven mode" ascii //weight: 1
        $x_1_3 = "Starting snake..." ascii //weight: 1
        $x_1_4 = "snake_start failed: 0x" ascii //weight: 1
        $x_1_5 = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

