rule Trojan_MSIL_FareIt_MBZS_2147905671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FareIt.MBZS!MTB"
        threat_id = "2147905671"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FareIt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 0b 07 17 59 0b 1f 64 07 5b 26 73 ?? 00 00 0a 0c 08}  //weight: 1, accuracy: Low
        $x_1_2 = "ordder2.Properties.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FareIt_SWA_2147931288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FareIt.SWA!MTB"
        threat_id = "2147931288"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FareIt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {45 0a 00 00 00 9f 00 00 00 72 00 00 00 d4 00 00 00 4e 00 00 00 d3 00 00 00 1d 01 00 00 44 00 00 00 8d 00 00 00 05 00 00 00 e9 00 00 00 38 9a 00 00 00 38 3a 00 00 00 20 03 00 00 00 28 ?? 00 00 06 3a ba ff ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {fe 0c 03 00 45 01 00 00 00 21 00 00 00 38 1c 00 00 00 11 05 28 ?? 00 00 06 20 00 00 00 00 28 ?? 00 00 06 39 dc ff ff ff 26 38 d2 ff ff ff dc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

