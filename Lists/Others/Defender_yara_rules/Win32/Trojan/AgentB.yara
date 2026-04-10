rule Trojan_Win32_AgentB_HVD_2147964632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentB.HVD!MTB"
        threat_id = "2147964632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 ff d5 32 06 32 c3 88 06 8b 44 24 ?? 40 83 f8 1c}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 04 0e 8a d3 32 01 f6 d2 32 c2 88 01 ?? ?? 88 11 43 41 83 fb 1c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentB_AHE_2147966721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentB.AHE!MTB"
        threat_id = "2147966721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {89 ca 45 8b 51 fc 49 83 e9 ?? c1 e2 ?? 31 ca 89 d0 c1 e8 ?? 31 d0 31 d2 89 c1 c1 e1 ?? 31 c1 89 c8 41 f7 f0 41 83 e8 ?? 49 8d 04 93 8b 10 41 89 11 41 83 f8 ?? 44 89 10 75}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

