rule TrojanDownloader_Win64_Snojan_DL_2147831967_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Snojan.DL!MTB"
        threat_id = "2147831967"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Snojan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c1 48 8b 8c 24 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f be 84 04 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 4c 24 40 48 8b 15 ?? ?? ?? ?? 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Snojan_ARA_2147947729_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Snojan.ARA!MTB"
        threat_id = "2147947729"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Snojan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 48 13 30 4c 14 48 ff c0 48 63 d0 48 83 fa 0d 72 ee}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

