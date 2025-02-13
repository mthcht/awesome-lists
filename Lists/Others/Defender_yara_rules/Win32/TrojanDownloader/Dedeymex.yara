rule TrojanDownloader_Win32_Dedeymex_A_2147648145_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dedeymex.A"
        threat_id = "2147648145"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dedeymex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xxccv.mysxc.info:777/loading/f.txt?dd=" ascii //weight: 1
        $x_1_2 = {6e 73 52 61 6e 64 6f 6d 2e 64 6c 6c 00 47 65 74 52 61 6e 64 6f 6d}  //weight: 1, accuracy: High
        $x_1_3 = {53 4f 46 54 57 41 52 45 5c 67 61 6e 6e 69 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 4f 46 54 57 41 52 45 5c 6f 6b 71 71 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

