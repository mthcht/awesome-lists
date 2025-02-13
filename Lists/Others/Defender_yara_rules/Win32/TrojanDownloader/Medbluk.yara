rule TrojanDownloader_Win32_Medbluk_A_2147687859_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Medbluk.A"
        threat_id = "2147687859"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Medbluk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "media.bulkweb.org/search.thn" ascii //weight: 1
        $x_1_2 = "speak.checknik.com/view.thn" ascii //weight: 1
        $x_1_3 = {47 45 54 20 7b 50 41 54 48 7d 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 7b 48 4f 53 54 7d 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 3b}  //weight: 1, accuracy: High
        $x_1_4 = {8b 47 44 8b 4c 24 1c 33 c3 85 c9 74 04 8b 31 eb 02 33 f6 0f c8 33 c6 8b 74 24 20 89 06 85 c9 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

