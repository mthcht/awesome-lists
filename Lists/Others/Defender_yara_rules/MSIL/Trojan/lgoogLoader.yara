rule Trojan_MSIL_lgoogLoader_MBAY_2147840058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/lgoogLoader.MBAY!MTB"
        threat_id = "2147840058"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "lgoogLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c 08 0d de 0b}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 00 4d 00 36 00 75 00 64 00 00 05 74 00 37 00 00 07 36 00 55 00 37 00 00 0d 71 00 57 00 57 00 4e 00 56 00 4a 00 00 05 69 00 72 00 00 0b 32 00 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_lgoogLoader_MBDV_2147845615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/lgoogLoader.MBDV!MTB"
        threat_id = "2147845615"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "lgoogLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tBdWs5w7QZroW2B65xbz+gD8StJPe" wide //weight: 1
        $x_1_2 = "+D8/4+k0M30BpXh20zc6ybIlcj5bag/xVw" wide //weight: 1
        $x_1_3 = "j7KX1bPgJJEUtC8kz8CTPZpx/hDVPE=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_lgoogLoader_MBDC_2147847214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/lgoogLoader.MBDC!MTB"
        threat_id = "2147847214"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "lgoogLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 0a 0c 08 04 16 04 8e 69 6f ?? 00 00 0a 0d de 0b}  //weight: 1, accuracy: Low
        $x_1_2 = {57 bf a2 3f 09 0a 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 36 00 00 00 25 00 00 00 a0 00 00 00 35 01 00 00 93 00 00 00 03 00 00 00 6e 00 00 00 16 00 00 00 94 01 00 00 01 00 00 00 01 00 00 00 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

