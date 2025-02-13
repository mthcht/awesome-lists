rule TrojanDownloader_Win64_SeStealer_A_2147905157_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/SeStealer.A!MTB"
        threat_id = "2147905157"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "SeStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8d 54 24 40 48 8b cd 44 89 7c 24 44 44 89 7c 24 40 ff 57 40 48 8d 4c 24 51 33 d2 41 b8 bb 02 00 00 44 88 7c 24 50 e8 ?? ?? ?? ?? 4c 8d 4c 24 44 48 8d 54 24 50 41 b8 bc 02 00 00 48 8b cd ff 57 50 8b 5c 24 44 8b ce 48 8d 54 24 50 49 03 cc}  //weight: 2, accuracy: Low
        $x_2_2 = {49 ff c0 ff c1 41 30 40}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

