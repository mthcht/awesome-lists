rule TrojanDownloader_Win32_Dalbot_A_2147657849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dalbot.A"
        threat_id = "2147657849"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dalbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {64 6f 77 6e 6c 6f 61 64 63 6f 70 79 3a 00 00 00 64 6f 77 6e 6c 6f 61 64 3a 00 00 00 67 65 74 75 72 6c 3a}  //weight: 2, accuracy: High
        $x_1_2 = "/logo.html" ascii //weight: 1
        $x_1_3 = "/logo.htmlEEEEEEEEEEEEEEEEEEEEEEsleep:" ascii //weight: 1
        $x_3_4 = {8a 0f 80 f1 ?? 46 88 08 8b 44 24 1c 3b c6 77 ac 6a 01}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

