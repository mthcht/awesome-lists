rule Trojan_Win32_Jinnir_A_2147609738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jinnir.A"
        threat_id = "2147609738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jinnir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 02 6a 00 6a fc 56 ff d5 8d 54 24 14 8d 44 24 10 6a 00 52 6a 04 50 56}  //weight: 2, accuracy: High
        $x_3_2 = {40 00 8b 44 24 10 b9 fc ff ff ff 6a 02 2b c8 6a 00 51 56 ff d5 8d 54 24 14 8b 44 24 10 6a 00 52 50 53 56}  //weight: 3, accuracy: High
        $x_2_3 = {8b 08 8d 55 e0 52 50 ff 51 34 8b 45 e0 3b c3 74 07 8b 00 3b 45 c4 74 ?? 8b 45 e4 8b 08}  //weight: 2, accuracy: Low
        $x_1_4 = "Internet Explorer_Server" ascii //weight: 1
        $x_1_5 = "WM_HTML_GETOBJECT" ascii //weight: 1
        $x_1_6 = "<IFRAME align=center" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

