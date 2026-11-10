rule Trojan_Win64_Muldrop_A_2147981824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Muldrop.A!MTB"
        threat_id = "2147981824"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Muldrop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {80 30 87 48 8d 70 01 80 70 01 87 80 70 02 87 48 83 c0 03 48 39 d8 75}  //weight: 30, accuracy: High
        $x_20_2 = {48 c7 44 24 50 ?? ?? ?? ?? b8 ?? ?? ?? ?? 48 33 44 24 50 ba ?? ?? ?? ?? 48 69 c0 ?? ?? ?? ?? 48 89 44 24 50}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*))) or
            (all of ($x*))
        )
}

