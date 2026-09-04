rule Trojan_Linux_GamblingGoblin_DA_2147977571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/GamblingGoblin.DA!MTB"
        threat_id = "2147977571"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "GamblingGoblin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "l5GX0xFv79zUDRfnkkW3tZbn10VZaB5yLH3okAU2qNSCr+rF1z9nvDEBs9o+ER1rdHP3LfKc7GPY/zL3yrJ6ceA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

