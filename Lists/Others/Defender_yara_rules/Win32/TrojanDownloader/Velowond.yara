rule TrojanDownloader_Win32_Velowond_A_2147623167_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Velowond.A"
        threat_id = "2147623167"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Velowond"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c6 02 53 68 ?? ?? ?? ?? 8d 4d e8 89 75 c4 e8 ?? ?? ?? ?? 8b f0 8d 4d e8 8d 7e 01 57 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 4d d4 89 45 10 e8 ?? ?? ?? ?? 8d 4d d8 c6 45 fc 09}  //weight: 2, accuracy: Low
        $x_1_2 = "%temppath%" ascii //weight: 1
        $x_1_3 = "%winpath%" ascii //weight: 1
        $x_1_4 = "%systempath%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

