rule TrojanDownloader_Win32_Donloblib_EM_2147898409_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Donloblib.EM!MTB"
        threat_id = "2147898409"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Donloblib"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 4d f0 c7 45 f0 00 00 00 00 51 68 00 04 00 00 8d 8d dc fb ff ff 51 50}  //weight: 5, accuracy: High
        $x_10_2 = "212.46.38.238/upd.php" ascii //weight: 10
        $x_10_3 = "162.19.214.208/upd.php" ascii //weight: 10
        $x_10_4 = "193.243.147.143/upd.php" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

