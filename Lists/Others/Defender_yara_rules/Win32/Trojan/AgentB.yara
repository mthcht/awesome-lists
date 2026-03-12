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

