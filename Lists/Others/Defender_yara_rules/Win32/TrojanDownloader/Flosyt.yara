rule TrojanDownloader_Win32_Flosyt_A_2147650254_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Flosyt.A"
        threat_id = "2147650254"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Flosyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 6c 75 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_2 = ".php?action=add&" ascii //weight: 1
        $x_1_3 = {ff 75 08 e8 ?? ?? ?? ?? 83 f8 2b 77 04 c9 c2 04 00 83 e8 2a 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

