rule TrojanDownloader_Win32_Cekar_B_2147597782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cekar.gen!B"
        threat_id = "2147597782"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cekar"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c9 89 4d f4 33 c9 89 4d f0 8b f8 4f 85 ff 7c 5b 47 33 c0 8b f0 8b ce c1 e1 02 03 ca 8b 09 03 4d fc 81 39 47 65 74 50 75 3e 8b d9 83 c3 04 81 3b 72 6f 63 41 75 31 8b d9 83 c3 08 81 3b 64 64 72 65 75 24 83 c1 0c 66 81 39 73 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cekar_C_2147597783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cekar.gen!C"
        threat_id = "2147597783"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cekar"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb f1 55 53 56 57 8b e8 03 40 3c 8b 78 78 03 fd 8b 77 20 03 f5 33 d2 8b 06 03 c5 81 38 47 65 74 50 75 32 81 78 04 72 6f 63 41 75 29 81 78 08 64 64 72 65 75 20 66 81 78 0c 73 73 75 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

