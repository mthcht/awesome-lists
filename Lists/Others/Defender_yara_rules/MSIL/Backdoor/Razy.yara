rule Backdoor_MSIL_Razy_G_2147745230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Razy.G!MTB"
        threat_id = "2147745230"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 00 4e 00 65 00 77 00 54 00 65 00 73 00 74 00 59 00 5c 00 4e 00 65 00 77 00 54 00 65 00 73 00 74 00 59 00 5c 00 [0-15] 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 [0-15] 2e 00 70 00 64 00 62 00}  //weight: 10, accuracy: Low
        $x_10_2 = {5c 4e 65 77 54 65 73 74 59 5c 4e 65 77 54 65 73 74 59 5c [0-15] 52 65 6c 65 61 73 65 5c [0-15] 2e 70 64 62}  //weight: 10, accuracy: Low
        $x_10_3 = {5c 00 4e 00 65 00 77 00 54 00 65 00 73 00 74 00 59 00 5c 00 6f 00 62 00 6a 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 [0-15] 2e 00 70 00 64 00 62 00}  //weight: 10, accuracy: Low
        $x_10_4 = {5c 4e 65 77 54 65 73 74 59 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c [0-15] 2e 70 64 62}  //weight: 10, accuracy: Low
        $x_1_5 = "icsharpcode.sharpziplib.pdb.compressed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

