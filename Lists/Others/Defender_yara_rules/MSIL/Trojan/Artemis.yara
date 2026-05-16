rule Trojan_MSIL_Artemis_NE_2147832166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Artemis.NE!MTB"
        threat_id = "2147832166"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Artemis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 04 00 00 06 28 07 00 00 06 6f 0e 00 00 0a 2a}  //weight: 5, accuracy: High
        $x_5_2 = {07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f 12 00 00 0a 08 17 58 0c 08 02 8e 69}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Artemis_NEA_2147832825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Artemis.NEA!MTB"
        threat_id = "2147832825"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Artemis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 09 07 09 07 8e 69 5d 91 02 09 91 61 d2 6f ?? 00 00 0a 09 17 58 0d 09 02 8e 69 32 e3}  //weight: 5, accuracy: Low
        $x_5_2 = {00 00 01 72 01 00 00 70 6f ?? 00 00 0a 72 ?? 00 00 70 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 26 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Artemis_AWB_2147832871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Artemis.AWB!MTB"
        threat_id = "2147832871"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Artemis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 9a 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 16 28 ?? ?? ?? 0a 2d 02 17 0a 08 17 d6}  //weight: 2, accuracy: Low
        $x_1_2 = "Service_ALTDNS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

