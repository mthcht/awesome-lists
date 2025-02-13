rule Trojan_MSIL_Gimmick_A_2147815703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gimmick.A"
        threat_id = "2147815703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gimmick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 00 57 00 6c 00 6a 00 63 00 6d 00 39 00 7a 00 62 00 32 00 5a 00 30 00 49 00 55 00 41 00 6a 00 4a 00 43 00 56 00 65 00 4a 00 69 00 6f 00 6f 00 4b 00 51 00 3d 00 3d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

