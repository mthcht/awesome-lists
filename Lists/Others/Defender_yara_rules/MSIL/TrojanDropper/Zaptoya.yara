rule TrojanDropper_MSIL_Zaptoya_A_2147726193_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Zaptoya.A!bit"
        threat_id = "2147726193"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zaptoya"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "For Each i In Split(Hex, \"******@@@@@@@@///////////***********@@@@@@@@@@++++++++\")" ascii //weight: 1
        $x_1_2 = {43 3a 5c 55 73 65 72 73 5c 44 45 4c 4c 5c 64 6f 63 75 6d 65 6e 74 73 5c 76 69 73 75 61 6c 20 73 74 75 64 69 6f 20 32 30 31 35 5c 50 72 6f 6a 65 63 74 73 5c [0-32] 5c [0-32] 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 68 72 6f 6d 65 53 65 74 75 70 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

