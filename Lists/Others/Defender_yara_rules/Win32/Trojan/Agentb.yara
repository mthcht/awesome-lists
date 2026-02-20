rule Trojan_Win32_Agentb_MK_2147963429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agentb.MK!MTB"
        threat_id = "2147963429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agentb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {0f b6 1c 0b 00 d3 0f b6 db 01 c3 32 1c 06 88 1c 06 00 d3 fe c3 0f b6 d3 41 3b 4c 24 10 bb 00 00 00 00 0f 44 cb 40 39 c7}  //weight: 20, accuracy: High
        $x_15_2 = {0f be c0 89 fe c1 e6 05 01 f7 01 c7 0f b6 03 43 84 c0}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

