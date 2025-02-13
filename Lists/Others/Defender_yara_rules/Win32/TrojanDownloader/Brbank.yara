rule TrojanDownloader_Win32_Brbank_A_2147725101_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Brbank.A"
        threat_id = "2147725101"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Brbank"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "itauaplicativo.exe" ascii //weight: 1
        $x_2_2 = {31 c0 39 c2 74 0a 80 b0 ?? ?? ?? ?? 08 40 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

