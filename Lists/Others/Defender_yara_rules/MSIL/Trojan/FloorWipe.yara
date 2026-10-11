rule Trojan_MSIL_FloorWipe_A_2147980121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FloorWipe.A!dha"
        threat_id = "2147980121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FloorWipe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5GtvXAzE92gVaz+wiuEpybkI6B7iYFNWX0Gh069jMHQ=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

