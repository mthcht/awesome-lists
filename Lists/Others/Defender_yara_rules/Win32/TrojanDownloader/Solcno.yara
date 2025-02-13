rule TrojanDownloader_Win32_Solcno_A_2147711824_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Solcno.A"
        threat_id = "2147711824"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Solcno"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 93 eb 9e 8d b4 26 00 00 00 00 c7 44 24 3b 43 6f 6e 6e c7 44 24 3f 65 63 74 69 31 ff c7 44 24 43 6f 6e 3a 20 c7 44 24 47 63 6c 6f 73 c7 44 24 4b 65 0d 0a 00 e9 0d ff ff ff 90}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 21 2e c6 44 24 22 62 c6 44 24 23 61 c6 44 24 24 74}  //weight: 1, accuracy: High
        $x_1_3 = {c7 40 08 5c 46 69 72 c7 40 0c 65 66 6f 78 c7 40 10 5c 50 72 6f c7 40 14 66 69 6c 65 66 c7 40 18 73 00 89 5c 24 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

