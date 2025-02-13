rule TrojanDownloader_Win32_Upranfef_A_2147648442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upranfef.A"
        threat_id = "2147648442"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upranfef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 70 65 6e 00 [0-7] 68 74 74 70 3a 2f 2f [0-48] 2f 75 70 64 61 74 2e 65 78 65 00 [0-7] 25 73 5c 25 73 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {99 59 f7 f9 8d 45 08 50 53 83 c2 61 89 55 08 e8 ?? ?? ?? ?? 59 4f 59 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

