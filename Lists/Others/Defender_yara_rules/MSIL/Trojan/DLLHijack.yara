rule Trojan_MSIL_DLLHijack_BAA_2147956593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DLLHijack.BAA!MTB"
        threat_id = "2147956593"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 11 04 91 1f 41 33 5b 06 11 04 17 58 91 1f 41 33 51 06 11 04 18 58 91 1f 41 33 47 06 11 04 19 58 91 1f 41 33 3d 16 13 05 2b 11 06 11 04 11 05 58 07 11 05 91 9c 11 05 17 58 13 05 11 05 07 8e 69 2f 0a 11 04 11 05 58 06 8e 69 32 de 11 04 07 8e 69 58 06 8e 69 2f 1a 06 11 04 07 8e 69 58 16 9c 2b 0f 11 04 17 58 13 04 11 04 06 8e 69 1a 59 32 8e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DLLHijack_DR_2147970596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DLLHijack.DR!MTB"
        threat_id = "2147970596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "://d565e3f03d0b1a7c8935d7ff94237316@o4511335034847232.ingest.de.sentry.io/4511337546317904" ascii //weight: 10
        $x_1_2 = "cliend_id:" ascii //weight: 1
        $x_1_3 = "pass:" ascii //weight: 1
        $x_1_4 = "oleto:" ascii //weight: 1
        $x_1_5 = "pfxPassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DLLHijack_ARR_2147972416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DLLHijack.ARR!MTB"
        threat_id = "2147972416"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 8e 69 28 ?? ?? ?? ?? 0a 02 06 16 06 8e 69 6f ?? ?? ?? ?? 02 03 16 03 8e 69}  //weight: 2, accuracy: Low
        $x_10_2 = {07 08 9a 0d 09 75 ?? 00 00 01 39 ?? 00 00 00 06 16 6f}  //weight: 10, accuracy: Low
        $x_5_3 = "$de344385-3a4d-45b2-a2a7-8722135f484d" ascii //weight: 5
        $x_3_4 = "Injector.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

