rule TrojanDownloader_Win64_Dukes_DA_2147842386_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Dukes.DA!MTB"
        threat_id = "2147842386"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Dukes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b 45 08 48 83 e8 10 48 39 c8 76 ?? 48 89 c8 31 d2 4c 8b 4c 24 50 48 f7 74 24 58 49 8b 45 00 41 8a 14 11 32 54 08 10 89 c8 41 0f af c0 31 c2 88 14 0b 48 ff c1 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

