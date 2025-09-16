rule Trojan_MSIL_OrcusRat_DNC_2147818575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OrcusRat.DNC!MTB"
        threat_id = "2147818575"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OrcusRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 08 91 6f ?? ?? ?? 0a 00 00 08 25 17 59 0c 16 fe 02 0d 09 2d e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_OrcusRat_NEAA_2147834123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OrcusRat.NEAA!MTB"
        threat_id = "2147834123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OrcusRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 17 9a 72 6d 00 00 70 02 18 9a 28 16 00 00 0a 28 02 00 00 06 2a 06}  //weight: 5, accuracy: High
        $x_4_2 = "Orcus.Golem" wide //weight: 4
        $x_4_3 = "/protectFile" wide //weight: 4
        $x_4_4 = "/launchClientAndExit" wide //weight: 4
        $x_4_5 = "/watchProcess" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_OrcusRat_ACU_2147841228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OrcusRat.ACU!MTB"
        threat_id = "2147841228"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OrcusRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 09 2b 2d 11 09 6f ?? ?? ?? 0a 13 0a 00 72 ?? ?? ?? 70 11 0a 2d 03 14 2b 07 11 0a}  //weight: 2, accuracy: Low
        $x_1_2 = "193.138.195.211" wide //weight: 1
        $x_1_3 = "Runner.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_OrcusRat_AOR_2147952316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OrcusRat.AOR!MTB"
        threat_id = "2147952316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OrcusRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 25 19 1f 25 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a a2 25 1a 72 ?? 0b 00 70 a2 25 1b 7e ?? 00 00 04 a2 25 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

