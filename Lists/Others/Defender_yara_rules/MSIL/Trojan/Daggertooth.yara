rule Trojan_MSIL_Daggertooth_C_2147838753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Daggertooth.C!dha"
        threat_id = "2147838753"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Daggertooth"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "i8p3aEeKQbN4klFMHmcC2dU9f6gORGIhDBLS0jP5Tn7o1AVJ" wide //weight: 1
        $x_1_2 = "8D29873B0B18F9C2F9E838DFFF59B" wide //weight: 1
        $x_1_3 = {02 1f 51 0a 12 00 28 ?? ?? ?? 0a 1f 26 0a 12 00 28 ?? ?? ?? 0a 1f 34 0a 12 00 28 ?? ?? ?? 0a 1f 67 0a 12 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

