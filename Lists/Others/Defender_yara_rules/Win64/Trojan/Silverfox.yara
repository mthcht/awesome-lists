rule Trojan_Win64_Silverfox_GVA_2147971858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Silverfox.GVA!MTB"
        threat_id = "2147971858"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Silverfox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 1e 89 fd 44 09 d5 41 89 fe 45 21 d6 41 0f af ee 81 e7 ?? ?? ?? ?? 45 31 d6 44 0f af f7 01 dd 89 ef 44 01 f7 48 ff c6 85 db 75 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

