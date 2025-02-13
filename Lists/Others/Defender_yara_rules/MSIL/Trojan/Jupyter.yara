rule Trojan_MSIL_Jupyter_AJY_2147841363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jupyter.AJY!MTB"
        threat_id = "2147841363"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jupyter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 8e 69 1b 59 8d ?? ?? ?? 01 0b 16 0d 2b 0c 07 09 06 09 1b 58 91 9c 09 17 58 0d 09 07 8e 69 32 ee}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jupyter_AJY_2147841363_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jupyter.AJY!MTB"
        threat_id = "2147841363"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jupyter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0c 2b 4c 07 08 07 08 91 07 08 17 58 91 61 d2 9c 07 8e 69 17 59 8d 21 00 00 01 0d 16 13 04 16 13 05 2b 1f 08 11 04 33 06 11 04 17 58 13 04 09 11 05 07 11 04 91 9c 11 04 17 58 13 04 11 05 17 58}  //weight: 2, accuracy: High
        $x_1_2 = "spacetruck.biz" wide //weight: 1
        $x_1_3 = "CS-DN/1.3" wide //weight: 1
        $x_1_4 = "\\AppData\\Local\\Google\\Chrome\\User Data" wide //weight: 1
        $x_1_5 = "jupyter" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jupyter_AJ_2147891437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jupyter.AJ!MTB"
        threat_id = "2147891437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jupyter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 15 13 0a 2b 28 11 09 7e 08 00 00 04 1a 9a 11 0a 17 da 17 6f 39 00 00 0a 28 3c 00 00 0a 28 3d 00 00 0a 6f 3e 00 00 0a 11 0a 17 d6 13 0a 11 0a 11 15 31 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

