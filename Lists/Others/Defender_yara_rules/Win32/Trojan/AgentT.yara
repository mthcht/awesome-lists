rule Trojan_Win32_AgentT_ST_2147762171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentT.ST!MTB"
        threat_id = "2147762171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 81 ce 00 ff ff ff 46 8a 84 35 ?? ?? ?? ?? 88 84 1d ?? ?? ?? ?? 8b 45 ?? 88 8c 35 ?? ?? ?? ?? 0f b6 8c 1d ?? ?? ?? ?? 03 ca 0f b6 c9 8a 8c 0d ?? ?? ?? ?? 30 0c 38 40 89 45 ?? 3b 45 10 72}  //weight: 1, accuracy: Low
        $x_1_2 = {59 8b c8 33 d2 8b c6 f7 f1 8a 0c 1a 30 0c 3e 46 3b 75 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

