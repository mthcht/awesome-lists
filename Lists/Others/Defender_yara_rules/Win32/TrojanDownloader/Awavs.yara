rule TrojanDownloader_Win32_Awavs_A_2147688737_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Awavs.gen!A"
        threat_id = "2147688737"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Awavs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 10 59 6a 04 33 db 58 f7 e1 0f 90 c3 89 4f 04 f7 db 0b d8 53 e8 ?? ?? ?? ?? 6a 08 89 47 08}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 d9 1b c9 99 81 e2 ff 01 00 00 03 c2 f7 d9 c1 f8 09 03 c8 c1 e1 09 51 89 0e e8 ?? ?? ?? ?? 8b f8 8b 46 04}  //weight: 1, accuracy: Low
        $x_2_3 = "<root><get_module botnet=\"%d\" name=\"%s\" bit=" ascii //weight: 2
        $x_1_4 = {63 66 67 00 62 6f 74 6e 65 74 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

