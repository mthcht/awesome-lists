rule Trojan_MSIL_Asyncrat_VN_2147759220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Asyncrat.VN!MTB"
        threat_id = "2147759220"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Asyncrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 07 02 07 91 11 ?? 61 09 06 91 61 d2 9c 06 03 6f ?? ?? ?? 0a 17 59 fe ?? 13 ?? 11 ?? 2c ?? 16 0a 2b ?? 06 17 58 0a 07 17 58 0b 07 02 8e 69 17 59 fe ?? 16 fe ?? 13 ?? 11 ?? 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Asyncrat_2147779243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Asyncrat!MTB"
        threat_id = "2147779243"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Asyncrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 38 a8 ff ?? ff 7e 13 00 ?? 04 14 28 63 00 ?? 06 3a b8 ff ?? ff 20 01 00 ?? 00 28 65 00 ?? 06 3a 8d ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = "wkqnWBmyQRgT3EdIQy.oIKKUP2ScqyZmjn13w" wide //weight: 1
        $x_1_3 = "us0QeIIyywHOnL1aEl.LLI7G23YMDKuEsuT7C" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Asyncrat_AMMC_2147904835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Asyncrat.AMMC!MTB"
        threat_id = "2147904835"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Asyncrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 09 06 09 91 08 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Asyncrat_SWA_2147936847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Asyncrat.SWA!MTB"
        threat_id = "2147936847"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Asyncrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 0e 00 00 04 2d 1c 28 ?? 00 00 06 14 fe 06 27 00 00 06 73 6d 00 00 0a 6f ?? 00 00 0a 17 80 0e 00 00 04 de 07 07 28 ?? 00 00 0a dc 7e 0d 00 00 04 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

