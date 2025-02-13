rule TrojanDownloader_Win32_Eltusk_A_2147624626_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Eltusk.gen!A"
        threat_id = "2147624626"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Eltusk"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 8f 56 22 0f 85 03 00 81 3c}  //weight: 1, accuracy: Low
        $x_1_2 = {e1 42 96 f0 e8}  //weight: 1, accuracy: High
        $x_1_3 = {80 34 08 23 8a 14 08 89 f7 0f b6 d2 81 e7 ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "st%03i00000.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

