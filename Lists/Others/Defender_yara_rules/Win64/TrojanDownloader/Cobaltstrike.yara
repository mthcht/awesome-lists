rule TrojanDownloader_Win64_Cobaltstrike_RRR_2147932729_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Cobaltstrike.RRR!MTB"
        threat_id = "2147932729"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tp://47.109.159.25:7080/29524.txt" ascii //weight: 1
        $x_1_2 = {48 8d 1d c9 e7 07 00 b9 23 00 00 00 e8 5a c0 fa ff 48 85 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

