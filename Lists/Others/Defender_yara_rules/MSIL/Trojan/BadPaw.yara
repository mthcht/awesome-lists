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

