rule Trojan_Win64_PoisonX_K_2147971926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoisonX.K!AMTB"
        threat_id = "2147971926"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoisonX"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F8284233-48F4-4680-ADDD-F8284233" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

