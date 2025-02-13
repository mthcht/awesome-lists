rule TrojanDownloader_Win32_Lepasud_A_2147650931_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lepasud.gen!A"
        threat_id = "2147650931"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lepasud"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 3e 33 d2 59 f7 f1 46 83 fe 0a 8a 82 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = "%s?mac=%s&ver=" ascii //weight: 1
        $x_1_3 = {6c 70 6b 2e 64 6c 6c 00 00 00 00 25 73 5c 25 73}  //weight: 1, accuracy: High
        $x_1_4 = {6d 66 78 69 78 75 65 2e 69 6e 69 00 00 00 00 25 73 5c 25 64 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_5 = {63 70 64 73 64 61 73 64 6c 75 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

