rule Trojan_MSIL_SoldierAudio_A_2147844032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SoldierAudio.A!dha"
        threat_id = "2147844032"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SoldierAudio"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Microsoft.NVIDIACorp.exe" wide //weight: 1
        $x_1_2 = {41 00 75 00 64 00 69 00 6f 00 43 00 61 00 72 00 64 00 [0-1] 44 00 72 00 69 00 76 00 65 00 72 00 [0-1] 53 00 65 00 72 00 76 00 69 00 63 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

