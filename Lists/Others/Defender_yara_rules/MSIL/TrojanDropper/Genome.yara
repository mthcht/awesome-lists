rule TrojanDropper_MSIL_Genome_SN_2147968906_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Genome.SN!MTB"
        threat_id = "2147968906"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genome"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {04 09 20 98 18 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 7e 78 00 00 0a 0b 07 20 be 18 00 00 28 ?? 00 00 06 17 6f 79 00 00 0a 0a 06 03 09 20 1c 19 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 17 6f 7a 00 00 0a}  //weight: 4, accuracy: Low
        $x_2_2 = "$cc729daa-2fef-4c91-9a4a-e22a2d120497" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

