rule Trojan_MSIL_CoinStealer_MBDN_2147845677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinStealer.MBDN!MTB"
        threat_id = "2147845677"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 08 02 1a 02 8e 69 1a 59 6f ?? 00 00 0a 28 6b 00 00 06 0c de 2d}  //weight: 1, accuracy: Low
        $x_1_2 = "ECNGrm81DXfmTAQi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinStealer_SK_2147891913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinStealer.SK!MTB"
        threat_id = "2147891913"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$187b3b12-185d-4ca8-b198-f8fff0105727" ascii //weight: 1
        $x_1_2 = "\\vanitygen\\vanitykitty\\btcgen\\obj\\Release\\btcgen.pdb" ascii //weight: 1
        $x_1_3 = "btcgen.Properties.Resources" ascii //weight: 1
        $x_1_4 = "btcgen.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinStealer_MDA_2147982613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinStealer.MDA!MTB"
        threat_id = "2147982613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 59 1a 6a 59 13 06 07 06 11 05 11 06 11 04}  //weight: 1, accuracy: High
        $x_1_2 = "stub.exe" wide //weight: 1
        $x_1_3 = "ConfusedByAttribut" ascii //weight: 1
        $x_1_4 = {57 9d a2 3d 09 0f 00 00 00 fa 25 33 00 16 00 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

