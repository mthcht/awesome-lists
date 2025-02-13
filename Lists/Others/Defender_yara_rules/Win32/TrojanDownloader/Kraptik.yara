rule TrojanDownloader_Win32_Kraptik_A_2147630497_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kraptik.gen!A"
        threat_id = "2147630497"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kraptik"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 eb ca ee 80 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 6d b3 29 d9 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 5e 1e c0 8f 53 68 7c 23 3a bf 52 68 00 00 00 00 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

