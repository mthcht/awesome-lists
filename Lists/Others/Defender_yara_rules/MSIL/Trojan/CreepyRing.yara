rule Trojan_MSIL_CreepyRing_A_2147819076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CreepyRing.A!dha"
        threat_id = "2147819076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CreepyRing"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ftp://41415.131417.114148.7:2121" wide //weight: 2
        $x_1_2 = "Ro#$%$#FC3#$%$#@RA#$%$#KZO#$%$#R" wide //weight: 1
        $x_1_3 = "d#$%$#Ac#$%$#kt#$%$#Y5#$%$#6##$%$#2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

