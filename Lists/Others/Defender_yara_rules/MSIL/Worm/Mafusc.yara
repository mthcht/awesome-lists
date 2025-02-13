rule Worm_MSIL_Mafusc_A_2147681675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Mafusc.A"
        threat_id = "2147681675"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mafusc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 61 00 64 00 64 00 26 00 61 00 3d 00 [0-4] 26 00 75 00 3d 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "schtasks.exe /Create /SC ONLOGON /TR " wide //weight: 1
        $x_1_3 = "?xxx=USB infection from" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

