rule TrojanDownloader_Win32_Jaik_AS_2147850824_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Jaik.AS!MTB"
        threat_id = "2147850824"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://51.79.49.73/" wide //weight: 1
        $x_1_2 = "ADODB.Stream" wide //weight: 1
        $x_1_3 = "SaveToFile" wide //weight: 1
        $x_1_4 = "Write" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Jaik_AJA_2147903157_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Jaik.AJA!MTB"
        threat_id = "2147903157"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 dc 89 45 e0 89 45 e4 89 45 e8 89 45 ec 89 45 f0 89 45 f4 89 45 f8 89 45 fc a1 ec 7f cb 00 33 c5 89 45 fc 89 4d f8 c7 45 e0 0b 00 00 00 c6 45 e4 21 c6 45 e5 14 c6 45 e6 2f c6 45 e7 20 c6 45 e8 1a c6 45 e9 2b c6 45 ea 13 c6 45 eb e6 c6 45 ec 2f c6 45 ed 14 c6 45 ee 2f c6 45 ef 0c c6 45 f0 3b c6 45 f1 d1 33 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Jaik_AJI_2147903158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Jaik.AJI!MTB"
        threat_id = "2147903158"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4b 04 8b 45 fc 8b 14 39 81 7c 02 fc cc cc cc cc 75 12 8b 44 39 04 03 c2 8b 55 fc 81 3c 10 cc cc cc cc 74 10 ff 74 39 08 8b 45 04 50 e8 02 1b 9c ff 83 c4 08 46 83 c7 0c 3b 33}  //weight: 1, accuracy: High
        $x_1_2 = {f8 c1 c0 03 66 f7 c1 df 13 66 85 e7 8d 80 85 fc 1e d0 f5 85 fc 35 37 72 e1 25}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

