rule Trojan_Win32_Nadostarch_A_2147680212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nadostarch.A"
        threat_id = "2147680212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nadostarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "torrnados.ru" ascii //weight: 1
        $x_1_2 = "/send_sms_24.php?tel=" ascii //weight: 1
        $x_1_3 = "/getop.php?tel=" ascii //weight: 1
        $x_1_4 = "&arhid=" ascii //weight: 1
        $x_1_5 = "KEY RRR" ascii //weight: 1
        $x_1_6 = "GO RRR" ascii //weight: 1
        $x_3_7 = {a5 a4 c7 85 f8 de ff ff 03 35 46 46 c7 85 f8 df ff ff 03 35 46 46}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

