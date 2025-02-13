rule TrojanDownloader_Win32_Conbatib_A_2147625913_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Conbatib.A"
        threat_id = "2147625913"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Conbatib"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 3e 68 0f 85 ?? 00 00 00 80 7e 01 74 0f 85 ?? 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {41 8b c1 33 c0 81 f9 df af ef ?? 75 f3}  //weight: 2, accuracy: Low
        $x_2_3 = {50 c6 06 30 c6 46 01 78 e8}  //weight: 2, accuracy: High
        $x_2_4 = {56 64 a1 30 00 00 00 8b 40 0c 8b 70 1c ad 8b 40 08}  //weight: 2, accuracy: High
        $x_1_5 = "%s\\%i%i%i%i%i.exe" ascii //weight: 1
        $x_1_6 = {62 61 63 6f 6e 62 69 74 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

