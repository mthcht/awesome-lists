rule Trojan_Win64_NightHawk_JK_2147836588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NightHawk.JK!MTB"
        threat_id = "2147836588"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NightHawk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 44 24 ?? 8b 44 24 ?? 48 3d ?? ?? ?? ?? 73 ?? 8b 44 24 ?? 48 8b 4c 24 ?? 0f b6 04 01 83 f0 ?? 8b 4c 24 ?? 88 84 0c ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NightHawk_A_2147892118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NightHawk.A!MTB"
        threat_id = "2147892118"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NightHawk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 ca 66 89 94 44 ?? ?? ?? ?? 48 83 c0 ?? 48 83 f8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

