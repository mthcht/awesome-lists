rule TrojanDownloader_Win32_Sagnusnagta_A_2147608827_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sagnusnagta.A"
        threat_id = "2147608827"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sagnusnagta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d7 81 e2 03 00 00 80 79 05 4a 83 ca fc 42 8a 44 14 18 8a 0e 32 c8 47 88 0e 46 3b f3 72 e1 5f 5e 5b c3}  //weight: 5, accuracy: High
        $x_1_2 = {25 73 25 64 25 64 2e 65 78 65 [0-16] 63 3a 5c [0-3] 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_2_3 = {68 74 74 70 3a 2f 2f [0-8] 2e 73 77 68 6d 7a 71 2e 63 6f 6d 2f}  //weight: 2, accuracy: Low
        $x_1_4 = {55 52 4c 00 [0-4] 25 64 [0-4] 63 3a 5c [0-3] 2e 64 61 74}  //weight: 1, accuracy: Low
        $x_1_5 = "?n=%s&id=%s&t=%s&i=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

