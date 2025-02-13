rule TrojanDownloader_Win32_Seadido_A_2147638121_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Seadido.A"
        threat_id = "2147638121"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Seadido"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 50 56 ff d3 6a 00 6a 00 68 40 04 00 00 56 ff d7}  //weight: 1, accuracy: High
        $x_1_2 = {6a 1a 50 6a 00 ff 15 ?? ?? ?? ?? 8d 4c 24 08 51 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

