rule TrojanDownloader_Win32_Flexty_A_2147651736_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Flexty.A"
        threat_id = "2147651736"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Flexty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {78 79 42 6f 74 2e 65 78 65 00 73 74 72 64 75 70}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 4e 02 c1 e3 08 b8 ?? ?? ?? ?? c6 06 01 03 d9 8d 50 01 8a 08 40 84 c9 75 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

