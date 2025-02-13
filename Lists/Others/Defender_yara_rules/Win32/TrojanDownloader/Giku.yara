rule TrojanDownloader_Win32_Giku_A_2147631841_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Giku.A"
        threat_id = "2147631841"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Giku"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 63 68 69 6c 61 69 2e 63 6f 6d 2f 73 79 73 74 65 6d 2f 6c 69 62 72 61 72 69 65 73 2f 74 65 70 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "GET /system/libraries/tep.txt HTTP/1.0" ascii //weight: 1
        $x_1_3 = {4c 44 31 35 45 39 46 45 38 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Giku_B_2147632957_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Giku.B"
        threat_id = "2147632957"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Giku"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 3b 45 08 72 12 8b 4d fc 8b 11 81 f2 ?? ?? ?? ?? 8b 45 fc 89 10 eb dd}  //weight: 1, accuracy: Low
        $x_1_2 = {73 18 8b 55 08 03 55 fc 0f be 02 35 ?? ?? ?? ?? 8b 4d 08 03 4d fc 88 01 eb d7}  //weight: 1, accuracy: Low
        $x_1_3 = "/tep.jpg" ascii //weight: 1
        $x_1_4 = "\\delme%04X.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

