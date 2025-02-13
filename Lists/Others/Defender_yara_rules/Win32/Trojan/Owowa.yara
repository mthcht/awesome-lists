rule Trojan_Win32_Owowa_B_2147807913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Owowa.B"
        threat_id = "2147807913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Owowa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "ExtenderControlDesigner" ascii //weight: 2
        $x_2_2 = "PreSend_RequestContent" ascii //weight: 2
        $x_2_3 = ".db.ses" ascii //weight: 2
        $x_2_4 = {75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 [0-16] 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00}  //weight: 2, accuracy: Low
        $x_2_5 = {75 73 65 72 6e 61 6d 65 [0-16] 70 61 73 73 77 6f 72 64}  //weight: 2, accuracy: Low
        $x_2_6 = "HealthMailbox " ascii //weight: 2
        $x_2_7 = "RunCommand" ascii //weight: 2
        $x_2_8 = {45 6e 63 72 79 70 74 [0-10] 53 74 61 72 74}  //weight: 2, accuracy: Low
        $x_2_9 = "\\S3crt\\source\\" ascii //weight: 2
        $x_4_10 = "dEUM3jZXaDiob8BrqSy2PQO1" wide //weight: 4
        $x_4_11 = "Fb8v91c6tHiKsWzrulCeqO" wide //weight: 4
        $x_4_12 = "jFuLIXpzRdateYHoVwMlfc" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_2_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

