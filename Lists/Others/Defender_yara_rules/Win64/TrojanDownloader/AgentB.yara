rule TrojanDownloader_Win64_AgentB_A_2147982489_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/AgentB.A!MTB"
        threat_id = "2147982489"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {44 8d 50 bf 44 0f b6 c8 83 c0 ?? 66 41 83 fa ?? 41 0f 43 c1 41 89 c9 48 83 c2 ?? 41 c1 e1 ?? 44 01 c9 0f b7 c0 01 c1 48 39 d6 74}  //weight: 30, accuracy: Low
        $x_20_2 = {44 0f b6 04 02 41 83 f0 ?? 44 88 04 01 44 0f b6 4a ?? 48 83 c0 ?? 44 39 c8 72}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

