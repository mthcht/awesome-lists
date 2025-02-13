rule TrojanDropper_MSIL_Muldalun_A_2147725433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Muldalun.A!bit"
        threat_id = "2147725433"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Muldalun"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " Add-MpPreference -ExclusionPath C:\\" wide //weight: 1
        $x_1_2 = {45 00 6e 00 63 00 65 00 64 00 46 00 69 00 6c 00 65 00 2e 00 61 00 65 00 73 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "DroppedFile2wdwerfghww543" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

