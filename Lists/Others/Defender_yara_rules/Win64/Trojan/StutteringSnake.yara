rule Trojan_Win64_StutteringSnake_H_2147980341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StutteringSnake.H"
        threat_id = "2147980341"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StutteringSnake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "No output" ascii //weight: 1
        $x_1_2 = "handle_message" ascii //weight: 1
        $x_1_3 = "send_message" ascii //weight: 1
        $x_1_4 = "__assert_armored__" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

