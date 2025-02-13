rule TrojanDownloader_Win32_Dunkerrgo_A_2147632222_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dunkerrgo.A"
        threat_id = "2147632222"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dunkerrgo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 fd 9a 80 5c 49 6e 65 74 4c 6f 61 64 2e 64 6c 6c 00 fe 1a 23 5c 69 6e 73 74 61 6c 6c 5f}  //weight: 1, accuracy: High
        $x_1_2 = {74 79 70 65 32 5f 74 2e 65 78 65 00 68 74 74 70 3a 2f 2f 64 6f 77 6e 2e 69 6e 70 72 69 76 61 63 79 2e 63 6f 2e 6b 72 2f 70 61 72 74 6e 65 72}  //weight: 1, accuracy: High
        $x_1_3 = "w.jjanfile.co.kr/count/install.php?pid=wintraroa" ascii //weight: 1
        $x_1_4 = {6d 6d 6f 6e 20 46 69 6c 65 73 00 31 00 fe a2 31 5c 77 69 6e 74 72 61 72 6f 61 64 5c 77 69 6e 74 72 61 72 6f 61 64 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

