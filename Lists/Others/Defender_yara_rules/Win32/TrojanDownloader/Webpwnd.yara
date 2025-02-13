rule TrojanDownloader_Win32_Webpwnd_A_2147625475_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Webpwnd.A"
        threat_id = "2147625475"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Webpwnd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 6f 6e 00 00 68 75 72 6c 6d 54 ff 16}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 40 80 3c 03 00 75 f9 c7 04 03 5c ?? 2e 65 c7 44 03 04 78 65 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Webpwnd_C_2147625898_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Webpwnd.C"
        threat_id = "2147625898"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Webpwnd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 6a 30 59 64 8b 29 8b 45 0c 8b 70 1c ad 8b 68 08 8b 75 3c 8b 74 2e 78 03 f5 56 8b 76 20 03 f5 33 c9 49 41 ad 03 c5 33 db 0f be 10 3a d6 74 08 c1 cb 07 03 da 40 eb f1 81 fb 67 59 de 1e 75 e3 5e 8b 5e 24 03 dd 66 8b 0c 4b 8b 5e 1c 03 dd 8b 04 8b 03 c5 bf 00 08 00 00 6a 40 68 00 10 00 00 57 6a 00 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

