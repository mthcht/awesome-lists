rule Trojan_MSIL_ShadowLoader_B_2147953254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShadowLoader.B!dha"
        threat_id = "2147953254"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShadowLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a 02 58 25 1e 64 61 7e ?? 00 00 04 58 25 1e 62 61 7e ?? 00 00 04 5a 25 1e 64 61 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

