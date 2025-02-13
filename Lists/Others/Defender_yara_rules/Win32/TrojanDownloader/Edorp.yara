rule TrojanDownloader_Win32_Edorp_A_2147625107_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Edorp.A"
        threat_id = "2147625107"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Edorp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 08 3f 00 0f 00 a1 ?? ?? ?? ?? 8b 84 85 ?? ?? ff ff 89 44 24 04 8b 45 f4 89 04 24 e8 ?? ?? ?? ?? 83 ec 0c 89 45 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 85 78 ff ff ff 89 44 24 08 a1 ?? ?? ?? ?? 8b 04 85 ?? ?? ?? ?? 89 44 24 04 8d 85 68 ff ff ff 89 04 24 c7 85 28 ff ff ff 12 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

