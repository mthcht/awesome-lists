rule Trojan_Win32_Stelpak_GCN_2147922499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelpak.GCN!MTB"
        threat_id = "2147922499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 1c ?? ?? ?? ?? 8b 4c 24 ?? 03 c2 0f b6 c0 89 74 24 ?? 0f b6 84 04 ?? ?? ?? ?? 30 04 39 47 3b 7c 24 ?? 0f 8c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stelpak_AMU_2147924662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelpak.AMU!MTB"
        threat_id = "2147924662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 19 85 f6 74 ?? 6a 01 8b ce e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

