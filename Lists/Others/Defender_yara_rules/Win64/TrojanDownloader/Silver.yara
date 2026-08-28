rule TrojanDownloader_Win64_Silver_PAHI_2147977147_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Silver.PAHI!MTB"
        threat_id = "2147977147"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Silver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "stage3b" ascii //weight: 2
        $x_1_2 = "Downloader started" ascii //weight: 1
        $x_2_3 = "generated/payloads" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

