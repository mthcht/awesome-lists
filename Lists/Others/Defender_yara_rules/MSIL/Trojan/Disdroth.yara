rule Trojan_MSIL_Disdroth_ADJ_2147898742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disdroth.ADJ!MTB"
        threat_id = "2147898742"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disdroth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 0a 17 0b 0e 04 2c 13 0e 04 17 33 1a 7e 5c 00 00 0a 02 6f 61 00 00 0a 0a 2b 0c 7e 5e 00 00 0a 02 6f 61 00 00 0a 0a 06 2c 09 06 03 04 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disdroth_EM_2147901905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disdroth.EM!MTB"
        threat_id = "2147901905"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disdroth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 1f a2 0b 09 07 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 42 00 00 00 1a 00 00 00 1a 00 00 00 3f 00 00 00 1f 00 00 00 08 00 00 00 66 00 00 00 08 00 00 00 15 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "SyncController" ascii //weight: 1
        $x_1_3 = "LiveFile.SyncOps" ascii //weight: 1
        $x_1_4 = "OpenWithDefaultProgram" ascii //weight: 1
        $x_1_5 = "WDSync.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disdroth_PTIT_2147902935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disdroth.PTIT!MTB"
        threat_id = "2147902935"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disdroth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 06 11 06 28 ?? 00 00 06 06 28 ?? 00 00 0a 2c 06 06 28 ?? 00 00 0a 08 06 28 ?? 00 00 0a de 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

