rule Trojan_Win64_ArcaneStealer_ARC_2147964563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ArcaneStealer.ARC!MTB"
        threat_id = "2147964563"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ArcaneStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "arcanepanel.cc" ascii //weight: 3
        $x_1_2 = "Brute.txt" ascii //weight: 1
        $x_1_3 = "arcane_boundary" ascii //weight: 1
        $x_1_4 = "ArcaneUploader/1.0" wide //weight: 1
        $x_1_5 = "Arcane/1.0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

