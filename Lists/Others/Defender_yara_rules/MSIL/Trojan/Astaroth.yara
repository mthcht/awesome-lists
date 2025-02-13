rule Trojan_MSIL_Astaroth_2147839680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Astaroth.psyS!MTB"
        threat_id = "2147839680"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Astaroth"
        severity = "Critical"
        info = "psyS: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {73 27 01 00 06 0d 09 07 08 9a 7d be 00 00 04 28 b3 01 00 0a 09 fe 06 28 01 00 06 73 78 00 00 0a 6f b4 01 00 0a 26 08 17 58 0c 08 07 8e 69 32 d0}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Astaroth_2147839689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Astaroth.psyV!MTB"
        threat_id = "2147839689"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Astaroth"
        severity = "Critical"
        info = "psyV: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {28 1d 00 00 0a 72 01 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c 28 20 00 00 0a 28 21 00 00 0a de 00 28 1d 00 00 0a 72 63 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Astaroth_2147839930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Astaroth.psyZ!MTB"
        threat_id = "2147839930"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Astaroth"
        severity = "Critical"
        info = "psyZ: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {73 75 01 00 06 0a 06 03 7d 06 01 00 04 00 00 7e d1 00 00 04 06 fe 06 76 01 00 06 73 dc 01 00 0a 6f dd 01 00 0a 00 73 6d 01 00 0a 80 d1 00 00 04 00 de 05 26 00 00 de 00 06 7b 06 01 00 04 04 05 0e 04 28 3f 02 00 06 00 02 72 38 fb 08 70 6f f3 00 00 0a a5 6e 00 00 01 0b 07 2c 10 06 7b 06 01 00 04 04 05 0e 04 28 2f 01 00 06 00}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

