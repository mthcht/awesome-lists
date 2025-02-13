rule TrojanDownloader_Win32_WebToos_A_2147692106_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/WebToos.A"
        threat_id = "2147692106"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "WebToos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8d 4f ff 83 c4 10 33 c0 85 c9 7e 11 8a 14 30 80 c2 77 80 f2 19 88 14 30 40 3b c1 7c ef}  //weight: 4, accuracy: High
        $x_1_2 = {75 70 6c 6f 61 64 69 74 65 6d 00 00 6e 6f 70 61 73 73 77 64}  //weight: 1, accuracy: High
        $x_1_3 = "Global\\ymgameupdate" ascii //weight: 1
        $x_1_4 = {55 50 44 41 54 45 44 41 54 41 00 00 57 69 6e 64 6f 77 73 20 75 70 64 61 74 65}  //weight: 1, accuracy: High
        $x_1_5 = {46 49 44 44 4c 45 52 2e 45 58 45 00 48 54 54 50 41 4e 41 4c 59 5a 45 52 53 54 44 56 33 2e 45 58 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

