rule Trojan_MSIL_Mimikatz_BA_2147798415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mimikatz.BA!MTB"
        threat_id = "2147798415"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mimikatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 06 16 73 ?? ?? ?? 0a 20 00 04 00 00 73 ?? ?? ?? 0a 0c 08 07 6f ?? ?? ?? 0a de 0a 08 2c 06 08 6f ?? ?? ?? 0a dc 07 6f ?? ?? ?? 0a 0d de 14}  //weight: 1, accuracy: Low
        $x_1_2 = "powershell_reflective_mimikatz" ascii //weight: 1
        $x_1_3 = "LoadMimiByCommand" ascii //weight: 1
        $x_1_4 = "MimikatzDelegate" ascii //weight: 1
        $x_1_5 = "LoadMimi" ascii //weight: 1
        $x_1_6 = "mimiBytes" ascii //weight: 1
        $x_1_7 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mimikatz_NWO_2147835149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mimikatz.NWO!MTB"
        threat_id = "2147835149"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mimikatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "br21r2671b2faowhl" ascii //weight: 10
        $x_10_2 = "dsa9uhda7syty2dd2" ascii //weight: 10
        $x_1_3 = {57 97 a2 3f 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "D84F4C120005F1837DC65C04181F3DA9466B123FC369C359" ascii //weight: 1
        $x_1_5 = "ftgyhuiopojhg" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Mimikatz_ASAU_2147849752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mimikatz.ASAU!MTB"
        threat_id = "2147849752"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mimikatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 04 11 05 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 28 ?? 00 00 0a 13 06 16 13 07 2b 1f 11 06 11 07 91 13 09 07 08 11 09 06 08 06 8e 69 5d 91 61 d2 9c 08 17 58 0c 11 07 17 58 13 07 11 07 11 06 8e 69 32 d9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

