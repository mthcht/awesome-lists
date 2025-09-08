rule Trojan_MSIL_Evilnum_SWA_2147929695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Evilnum.SWA!MTB"
        threat_id = "2147929695"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Evilnum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 09 08 6f 14 00 00 0a 6f ?? 00 00 0a 26 11 04 6f ?? 00 00 0a 09 6f ?? 00 00 0a 00 09 16 09 6f ?? 00 00 0a 6f ?? 00 00 0a 26 00 17 13 05 2b d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Evilnum_SWB_2147929696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Evilnum.SWB!MTB"
        threat_id = "2147929696"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Evilnum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 09 08 6f 20 00 00 0a 6f 21 00 00 0a 26 11 04 6f 22 00 00 0a 09 6f 23 00 00 0a 00 09 16 09 6f 24 00 00 0a 6f 25 00 00 0a 26 00 17 13 05 2b d0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Evilnum_PGE_2147951758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Evilnum.PGE!MTB"
        threat_id = "2147951758"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Evilnum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 08 6f 1c 00 00 0a 6f ?? 00 00 0a 26 11 04 6f ?? 00 00 0a 09 6f ?? 00 00 0a 00 09 16 09 6f ?? 00 00 0a 6f ?? 00 00 0a 26 00 17 13 05 2b d0}  //weight: 10, accuracy: Low
        $x_10_2 = {0a 09 08 6f ?? 00 00 0a 6f ?? 00 00 0a 26 11 04 6f ?? 00 00 0a 09 6f ?? 00 00 0a 09 16 09 6f ?? 00 00 0a 6f ?? 00 00 0a 26 2b d6 08 2c 06 08 6f ?? 00 00 0a dc}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

