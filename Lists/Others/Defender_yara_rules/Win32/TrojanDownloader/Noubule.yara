rule TrojanDownloader_Win32_Noubule_A_2147626993_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Noubule.A"
        threat_id = "2147626993"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Noubule"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 02 6a 00 68 0c fe ff ff 56 ff 15 ?? ?? 40 00 68 f4 01 00 00 e8 ?? ?? 00 00 83 c4 04 8d 55 fc 8b f8 6a 00 52 68 f4 01 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = "%s?mac=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

