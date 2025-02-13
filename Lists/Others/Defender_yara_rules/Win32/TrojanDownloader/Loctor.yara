rule TrojanDownloader_Win32_Loctor_A_2147626260_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Loctor.A"
        threat_id = "2147626260"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Loctor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 68 65 20 4c 75 61 4f 72 62 20 52 65 61 63 74 6f 72 00 00 73 65 74 75 70 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? ?? 89 85 ?? ?? ff ff c6 85 ?? ?? ff ff 02 c6 85 ?? ?? ff ff 00 8b 8d ?? ?? ff ff [0-2] ff 00 00 00 8b ?? ?? ?? ff ff [0-2] ff 00 00 00 3b ?? 0f 85 be 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

