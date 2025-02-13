rule TrojanDownloader_Win32_Emuvito_A_2147610184_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Emuvito.A"
        threat_id = "2147610184"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Emuvito"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3b 58 75 f8 80 7b 01 58 75 f2 80 7b 02 58 75 ec 89 1d ?? ?? 42 00 a1 ?? ?? 42 00 83 78 14 00 0f 85 7b 03 00 00 a1 ?? ?? 42 00 8b 58 04}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 10 80 f2 ?? 88 10 43 40 83 fb 0d 75 f2}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d8 8a 83 ?? ?? 42 00 e8 ?? ?? ?? ff 3c 45 0f 84 dd 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

