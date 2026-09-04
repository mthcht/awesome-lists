rule Trojan_Win64_HardBreacher_DA_2147977565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HardBreacher.DA!MTB"
        threat_id = "2147977565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HardBreacher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Local\\HardBreacher-SolidSnake-Sync-Event" ascii //weight: 10
        $x_1_2 = "SOFTWARE\\WOW6432Node\\KasperskyLab\\protected\\KES" ascii //weight: 1
        $x_1_3 = "SolidSnake.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

