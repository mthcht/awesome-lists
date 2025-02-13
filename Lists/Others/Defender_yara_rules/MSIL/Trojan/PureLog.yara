rule Trojan_MSIL_PureLog_RDA_2147903489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLog.RDA!MTB"
        threat_id = "2147903489"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 28 11 00 00 0a 28 12 00 00 0a 11 04 6f 13 00 00 0a 13 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLog_RDB_2147904777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLog.RDB!MTB"
        threat_id = "2147904777"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Goteye" ascii //weight: 1
        $x_1_2 = "Microsomes" ascii //weight: 1
        $x_1_3 = "MSG_NET" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLog_RDC_2147905466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLog.RDC!MTB"
        threat_id = "2147905466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 03 00 00 0a 28 01 00 00 2b 72 01 00 00 70 6f 05 00 00 0a 14 14}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLog_RDE_2147909497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLog.RDE!MTB"
        threat_id = "2147909497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 05 73 03 00 00 0a 0b 11 04 73 0c 00 00 0a 0c 08 11 05 16 73 0d 00 00 0a 0d 09 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLog_RDF_2147910097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLog.RDF!MTB"
        threat_id = "2147910097"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 09 28 c2 00 00 0a 72 61 01 00 70 6f c3 00 00 0a 6f c4 00 00 0a 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLog_RDG_2147912648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLog.RDG!MTB"
        threat_id = "2147912648"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 06 28 06 00 00 0a 6f 07 00 00 0a 08 07 28 06 00 00 0a 6f 08 00 00 0a 08 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLog_RDH_2147912757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLog.RDH!MTB"
        threat_id = "2147912757"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 09 07 18 6f 82 00 00 0a 1f 10 28 83 00 00 0a 6f 51 00 00 0a 07 18 58 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLog_RDI_2147912758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLog.RDI!MTB"
        threat_id = "2147912758"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 06 6f 5b 00 00 0a 06 6f 5c 00 00 0a 6f 5d 00 00 0a 0b 1b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLog_RDJ_2147913416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLog.RDJ!MTB"
        threat_id = "2147913416"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A7D072E4-57C9-48F1-A9E2-AE58DFEB176C" ascii //weight: 1
        $x_1_2 = "ZeroByte943" ascii //weight: 1
        $x_1_3 = "Zerobyte9851" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLog_ARA_2147913549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLog.ARA!MTB"
        threat_id = "2147913549"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 09 58 0c 06 07 08 07 8e 69 08 59 6f ?? ?? ?? 0a 25 0d 16 30 ea}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLog_ARA_2147913549_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLog.ARA!MTB"
        threat_id = "2147913549"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WD KILLER.g.resources" ascii //weight: 2
        $x_2_2 = "$55914539-1b90-4d74-96d0-ff1c841591fd" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLog_ARA_2147913549_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLog.ARA!MTB"
        threat_id = "2147913549"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RDiqTGmAQDTM96X6Xy.q0asJylmpbVdFhZFLX" ascii //weight: 2
        $x_2_2 = "qkcidBv5UxcAGF25SD.23cQf1YgbFwJiruPEJ" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLog_RDK_2147913682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLog.RDK!MTB"
        threat_id = "2147913682"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0a0d24e1-121b-4680-8ee7-430a758d20db" ascii //weight: 1
        $x_2_2 = {07 09 18 6f 10 00 00 0a 1f 10 28 11 00 00 0a 13 04 11 04 16 25}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLog_KAG_2147919016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLog.KAG!MTB"
        threat_id = "2147919016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 0d 58 11 06 11 03 95 58 20 ff 00 00 00 5f 13 04 ?? ?? ?? ?? ?? 11 0e 11 10 61 13 13}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLog_RDQ_2147919038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLog.RDQ!MTB"
        threat_id = "2147919038"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "095a5c88-d365-4c54-9aff-d168cb28ed00" ascii //weight: 2
        $x_1_2 = "musicSDplayer" ascii //weight: 1
        $x_1_3 = "Speccy Installer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

