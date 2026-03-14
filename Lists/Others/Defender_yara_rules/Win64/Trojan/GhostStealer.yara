rule Trojan_Win64_GhostStealer_AMTB_2147964748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GhostStealer!AMTB"
        threat_id = "2147964748"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GhostStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\Temp\\ghost_" ascii //weight: 1
        $x_1_2 = "GhostStealer.pdb" ascii //weight: 1
        $x_1_3 = "C:\\Windows\\Temp\\data_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

