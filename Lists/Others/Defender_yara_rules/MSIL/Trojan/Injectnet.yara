rule Trojan_MSIL_Injectnet_NUB_2147964168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injectnet.NUB!MTB"
        threat_id = "2147964168"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injectnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 44 00 65 00 62 00 75 00 67 00 5c 00 6d 00 61 00 69 00 6e 00 5c 00 6f 00 62 00 6a 00 5c 00 44 00 65 00 62 00 75 00 67 00 5c 00 [0-48] 2e 00 70 00 64 00 62 00}  //weight: 2, accuracy: Low
        $x_2_2 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 44 65 62 75 67 5c 6d 61 69 6e 5c 6f 62 6a 5c 44 65 62 75 67 5c [0-48] 2e 70 64 62}  //weight: 2, accuracy: Low
        $x_2_3 = "GrafikkarteSBbRA0" ascii //weight: 2
        $x_1_4 = "VirusBDxUA0" ascii //weight: 1
        $x_1_5 = "PhishingkbxrA0" ascii //weight: 1
        $x_1_6 = "viarUNTZ0" ascii //weight: 1
        $x_1_7 = "oportunidadBelbX0" ascii //weight: 1
        $x_1_8 = "WebseitebmRMX0" ascii //weight: 1
        $x_1_9 = "technologygdcjU0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

