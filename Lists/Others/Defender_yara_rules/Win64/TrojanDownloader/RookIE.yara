rule TrojanDownloader_Win64_RookIE_A_2147852085_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/RookIE.A!MTB"
        threat_id = "2147852085"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "RookIE"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8d 8c 24 60 04 00 00 41 b8 ff 03 00 00 48 8d 54 24 30 48 8b cf ff 15 ?? 40 01 00 44 8b 84 24 60 04 00 00 48 8d 54 24 30 48 63 cb 48 03 ce e8 ?? 38 00 00 8b 84 24 60 04 00 00 03 d8 85 c0 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_RookIE_B_2147889535_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/RookIE.B!MTB"
        threat_id = "2147889535"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "RookIE"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RookIE/1.0" ascii //weight: 2
        $x_2_2 = "s64.jpg" ascii //weight: 2
        $x_2_3 = "Console" ascii //weight: 2
        $x_2_4 = "oss-cn-hangzhou.aliyuncs.com" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

