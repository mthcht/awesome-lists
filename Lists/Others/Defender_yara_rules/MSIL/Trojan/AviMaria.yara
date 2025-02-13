rule Trojan_MSIL_AviMaria_FF_2147826842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AviMaria.FF!MTB"
        threat_id = "2147826842"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AviMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 28 1f 00 00 0a 03 6f 20 00 00 0a 6f 21 00 00 0a 0c 73 22 00 00 0a 13 06 11 06 08 6f 23 00 00 0a 11 06 18 6f 24 00 00 0a 11 06 18 6f 25 00 00 0a 11 06 0d}  //weight: 10, accuracy: High
        $x_10_2 = {2b 22 2b 23 2b 28 2b 2a 06 16 06 8e 69 6f 26 00 00 0a 13 05 28 1f 00 00 0a 11 05 6f 27 00 00 0a 13 07 de 26 09 2b db 6f 28 00 00 0a 2b d6 13 04 2b d4 11 04 2b d2}  //weight: 10, accuracy: High
        $x_1_3 = "sfgp" ascii //weight: 1
        $x_1_4 = "sbfg" ascii //weight: 1
        $x_1_5 = "sfggfs" ascii //weight: 1
        $x_1_6 = "Geedfdfks" ascii //weight: 1
        $x_1_7 = "Directfnot fsist" ascii //weight: 1
        $x_1_8 = "Gefedffdfks" ascii //weight: 1
        $x_1_9 = "cekrgch" ascii //weight: 1
        $x_1_10 = "fsaddsdfsa" ascii //weight: 1
        $x_1_11 = "PoweredByAttribute" ascii //weight: 1
        $x_1_12 = "C:\\sdfdfry\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

