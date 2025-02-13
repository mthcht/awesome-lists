rule Backdoor_MSIL_Pandora_SP_2147837090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Pandora.SP!MTB"
        threat_id = "2147837090"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pandora"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {18 5b 2b 41 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 08 18 58 16 2d fb 0c 08 18 2c cd 06 16 2d f3 32 d8 19 2c d5 07 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "DiscoverSales_1.exe" ascii //weight: 1
        $x_1_3 = "filifilm.com.br/images/colors/purple/Bqvoou.png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Pandora_MBZQ_2147905121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Pandora.MBZQ!MTB"
        threat_id = "2147905121"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pandora"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 05 03 11 04 1f fe 28 ?? 00 00 0a 6f ?? 00 00 0a 1f ?? 28 ?? 00 00 0a 28 ?? 00 00 0a 08 11 05 09 5d 91 61 d2 9c 11 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

