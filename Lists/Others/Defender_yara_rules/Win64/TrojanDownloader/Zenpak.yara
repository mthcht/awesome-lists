rule TrojanDownloader_Win64_Zenpak_CCEJ_2147897302_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Zenpak.CCEJ!MTB"
        threat_id = "2147897302"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 54 24 ?? 48 89 7c 24 40 48 8d b8 ?? ?? ?? ?? 4c 8d 4c 24 ?? 48 8b cf 41 b8 40 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "payload.bin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Zenpak_CCHU_2147903509_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Zenpak.CCHU!MTB"
        threat_id = "2147903509"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 18 01 00 00 45 33 c9 48 8d 15 ?? ?? ?? ?? 48 8b c8 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

