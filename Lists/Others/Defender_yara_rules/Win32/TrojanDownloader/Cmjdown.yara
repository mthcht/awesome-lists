rule TrojanDownloader_Win32_Cmjdown_G_2147602479_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cmjdown.G"
        threat_id = "2147602479"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cmjdown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 02 6a fc 8d 45 f4 50 e8 ?? ?? ?? ff 6a 04 8d 45 f0 50 8d 45 f4 50 e8 ?? ?? ?? ff 6a 02 8b 45 f0 83 c0 04 f7 d8 50 8d 45 f4 50 e8 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = {6a 00 6a 00 ff 75 14 6a 00 6a 01 ff 75 10 ff 75 0c e8 ?? ?? ?? 00 89 07 83 3f ff 75 04 31 c0 eb 0f 6a 00 ff 37 e8 ?? ?? ?? 00 89 47 08}  //weight: 1, accuracy: Low
        $x_1_3 = "HTTP-CMJ-DOWNLOAD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

