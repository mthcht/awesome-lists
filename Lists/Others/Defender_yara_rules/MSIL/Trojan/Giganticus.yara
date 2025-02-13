rule Trojan_MSIL_Giganticus_B_2147812961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Giganticus.B!dha"
        threat_id = "2147812961"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Giganticus"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "f49adad4-576c-4c07-9911-90f4b9058d92" ascii //weight: 1
        $x_1_2 = {1f 66 0a 12 00 28 ?? ?? ?? 0a a2 25 17 1f 34 0a 12 00 28 ?? ?? ?? 0a a2 25 18 1f 39 0a 12 00 28 ?? ?? ?? 0a a2 25 19 1f 61 0a 12 00 28 ?? ?? ?? 0a a2 25 1a 1f 64 0a 12 00 28 ?? ?? ?? 0a a2 25 1b 1f 61 0a 12 00 28 ?? ?? ?? 0a a2 25 1c 1f 64 0a 12 00 28 ?? ?? ?? 0a a2 25 1d 1f 34 0a 12 00 28 ?? ?? ?? 0a a2 25 1e 1f 2d 0a 12 00 28 ?? ?? ?? 0a a2 25 1f 09 1f 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

