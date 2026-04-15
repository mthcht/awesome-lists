rule Trojan_MSIL_Alien_MK_2147962011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Alien.MK!MTB"
        threat_id = "2147962011"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Alien"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_35_1 = {74 03 00 00 01 0b 07 6f 03 00 00 0a 73 04 00 00 0a 6f 05 00 00 0a 0c 28 06 00 00 0a 0d 09 08 6f 07 00 00 0a 26 09 6f 08 00 00 0a}  //weight: 35, accuracy: High
        $x_5_2 = "http://" ascii //weight: 5
        $x_5_3 = "https://" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_35_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Alien_SL_2147967073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Alien.SL!MTB"
        threat_id = "2147967073"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Alien"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "$436BD42B-CCCF-4E06-BBDA-CC7D49E3A618" ascii //weight: 4
        $x_4_2 = "exe.renaelCCC/sj/or.mor-ilec//:sptth" ascii //weight: 4
        $x_1_3 = "NtAllocateVirtualMemory" ascii //weight: 1
        $x_1_4 = ":wen!rotartsinimdA:noitavelE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

