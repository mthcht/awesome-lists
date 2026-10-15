rule Trojan_MSIL_BadPaw_MKV_2147964126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BadPaw.MKV!MTB"
        threat_id = "2147964126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BadPaw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 07 00 9c 20 c8 00 00 00 38 05 e9 ff ff 11 08 1f 09 11 00 1a 91 9c 20 62 00 00 00 28 ?? 00 00 06 39 ed e8 ff ff 26 20 37 00 00 00 38 e2 e8 ff ff fe 0c 04 00 20 04 00 00 00 20 db 00 00 00 20 49 00 00 00 59 9c 20 ed 00 00 00 28 ?? 00 00 06 39 be e8 ff ff 26 20 9c 00 00 00 38 b3 e8 ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BadPaw_AW_2147980404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BadPaw.AW!MTB"
        threat_id = "2147980404"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BadPaw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 3c 00 00 00 28 ?? 00 00 06 72 ed 04 00 70 28 ?? 00 00 0a 72 ff 04 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 20 27 00 00 02 28 ?? 01 00 06 28 ?? 00 00 0a 28 ?? 01 00 0a 74 27 00 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {3a 46 00 00 00 28 ?? 00 00 06 72 0b 05 00 70 28 ?? 00 00 0a 72 19 05 00 70 28 ?? 00 00 0a 72 2b 05 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 20 28 00 00 02 28 ?? 01 00 06 28 ?? 00 00 0a 28 ?? 01 00 0a 74 28}  //weight: 1, accuracy: Low
        $x_1_3 = {3a 3c 00 00 00 28 ?? 00 00 06 72 ed 04 00 70 28 ?? 00 00 0a 72 39 05 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 20 29 00 00 02 28 ?? 01 00 06 28 ?? 00 00 0a 28 ?? 01 00 0a 74 29 00 00 02 80 62 00 00 04 7e}  //weight: 1, accuracy: Low
        $x_1_4 = {3a 3c 00 00 00 28 ?? 00 00 06 72 49 05 00 70 28 ?? 00 00 0a 72 55 05 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 20 2a 00 00 02 28 ?? 01 00 06 28 ?? 00 00 0a 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

