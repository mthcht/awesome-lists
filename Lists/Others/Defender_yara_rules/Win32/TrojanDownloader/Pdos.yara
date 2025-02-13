rule TrojanDownloader_Win32_Pdos_A_2147631877_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pdos.A"
        threat_id = "2147631877"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pdos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 64 6f 73 2e 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {f3 ab 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 85 c0 55 16 8b f4 6a 05 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 2b f4 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 69 6e 45 78 65 63 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

