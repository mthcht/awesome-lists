rule Trojan_Win64_AgentB_AHA_2147966523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentB.AHA!MTB"
        threat_id = "2147966523"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {44 0f b6 42 fc 44 09 c0 44 0f b6 42 ff 41 c1 e0 ?? 44 09 c0 89 84 0c d0 00 00 00 48 83 c1 ?? 48 83 f9 ?? 75}  //weight: 30, accuracy: Low
        $x_20_2 = {41 89 ca 88 4a fc 88 6a fd 41 c1 ea ?? c1 e9 ?? 44 88 52 fe 88 4a ff 49 83 f9 ?? 75}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

