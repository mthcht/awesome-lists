rule TrojanDownloader_Win64_Phorpiex_C_2147967804_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Phorpiex.C!MTB"
        threat_id = "2147967804"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b8 6b 00 00 00 66 89 44 24 ?? b8 65 00 00 00 66 89 44 24 ?? b8 72 00 00 00 66 89 44 24 ?? b8 6e 00 00 00 66 89 44 24 ?? b8 65 00 00 00 66 89 44 24 ?? b8 6c 00 00 00 66 89 44 24 ?? b8 33 00 00 00 66 89 44 24 ?? b8 32}  //weight: 5, accuracy: Low
        $x_5_2 = {b8 68 00 00 00 66 89 84 24 ?? ?? ?? ?? b8 74 00 00 00 66 89 84 24 ?? ?? ?? ?? b8 74 00 00 00 66 89 84 24 ?? ?? ?? ?? b8 70 00 00 00 66 89 84 24 ?? ?? ?? ?? b8 3a 00 00 00 66 89 84 24 ?? ?? ?? ?? b8 2f 00 00 00 66 89 84 24 ?? ?? ?? ?? b8 2f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

