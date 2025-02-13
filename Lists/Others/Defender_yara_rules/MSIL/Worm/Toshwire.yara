rule Worm_MSIL_Toshwire_A_2147639318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Toshwire.A"
        threat_id = "2147639318"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Toshwire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-crack.exe" wide //weight: 1
        $x_1_2 = "DisableCMD" wide //weight: 1
        $x_1_3 = "DisableRegistryTools" wide //weight: 1
        $x_1_4 = "signon" wide //weight: 1
        $x_1_5 = "\\limewire\\shared\\" wide //weight: 1
        $x_1_6 = {6e 20 50 45 00 00 6a fe 01 16 fe 01 12 0c 7b 56 00 00 04 20 4d 5a 00 00 fe 01 16 fe 01 60 2c 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

