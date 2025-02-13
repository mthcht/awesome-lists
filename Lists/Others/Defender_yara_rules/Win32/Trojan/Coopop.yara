rule Trojan_Win32_Coopop_B_2147678536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coopop.B"
        threat_id = "2147678536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coopop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 49 45 4e 41 4d 45 00 00 53 45 54 00 49 53 4c 41 58 43 48 45 43 4b 00 00 49 45 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 04 11 f6 d0 88 04 11 8b c1 49 85 c0 7f f1}  //weight: 1, accuracy: High
        $x_1_3 = {68 1f 00 02 00 53 68 48 c1 00 10 68 01 00 00 80 89 ?? ?? 18 89 ?? ?? 24 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coopop_B_2147678536_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coopop.B"
        threat_id = "2147678536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coopop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 31 6a c5 00 68 40 1f 00 00 89 86 14 03 00 00 89 86 20 03 00 00 89 86 18 03 00 00 8d 44 24 24 8d be b8 00 00 00 56 50 68 52 00 00 50}  //weight: 2, accuracy: High
        $x_2_2 = "adunion/reportmac.asp?mac=%s&iip=%s&bianma=%s&ver=ie" ascii //weight: 2
        $x_1_3 = "un.58wb.com/search.asp" ascii //weight: 1
        $x_1_4 = "TAOKEID" ascii //weight: 1
        $x_1_5 = "YOUDAOID" ascii //weight: 1
        $x_1_6 = "SOGOUID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

