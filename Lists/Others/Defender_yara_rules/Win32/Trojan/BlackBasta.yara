rule Trojan_Win32_BlackBasta_BG_2147835487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackBasta.BG!MTB"
        threat_id = "2147835487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackBasta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 e1 c1 ea 03 6b d2 19 8b c1 2b c2 8a 90 ?? ?? ?? ?? 8d 34 39 32 14 2e 83 c1 01 3b cb 88 16 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BlackBasta_AB_2147836381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackBasta.AB!MTB"
        threat_id = "2147836381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackBasta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c1 88 45 fe 0f b7 55 f8 8b 45 a0 0f b7 08 d3 fa 8b 4d b4 66 89 11 8b 55 c4 8b 02 8b 4d e4 d3 e0 89 45 88 8b 4d 94 8b 55 dc 8b 01 2b 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

