rule TrojanDownloader_Win32_Kaliox_A_2147653921_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kaliox.A"
        threat_id = "2147653921"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kaliox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 00 00 00 a0 6a ff 68 44 61 00 10 52 ff 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8d 44 24 ?? 6a 04 50 6a 06 52 c7 44 24 ?? 00 5c 26 05 ff d6}  //weight: 2, accuracy: Low
        $x_2_2 = {5c 77 69 6e 69 6e 65 74 2e 64 6c 6c 00 00 00 00 69 64 65 6f 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_1_3 = {49 45 63 6f 72 65 4f 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 4e 66 69 6c 65 2e 61 73 70 00}  //weight: 1, accuracy: High
        $x_1_5 = "ProcGo" ascii //weight: 1
        $x_1_6 = "GetFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

