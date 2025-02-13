rule TrojanDownloader_Win32_Begseabug_A_2147643051_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Begseabug.A"
        threat_id = "2147643051"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Begseabug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SeBebugPrivilege" ascii //weight: 1
        $x_1_2 = {63 6f 6d 3a 38 30 38 30 [0-6] 2f 73 63 2e 70 6e 67}  //weight: 1, accuracy: Low
        $x_1_3 = {68 2d af 9c 4e}  //weight: 1, accuracy: High
        $x_1_4 = "SYSTEM32\\system.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Begseabug_A_2147643051_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Begseabug.A"
        threat_id = "2147643051"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Begseabug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 81 ec 74 08 00 00 8b 45 c4 53 33 db 56 3b c3 57 be 1f ab 01 01 74 ?? be 1f ab 01 01 b9 81 00 00 00}  //weight: 5, accuracy: Low
        $x_5_2 = {8a 04 1a 88 45 ff 8a 45 ff c0 c0 03 88 45 ff 8a 45 ff 32 44 0d c8 41 83 f9 10 88 04 1a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

