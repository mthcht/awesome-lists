rule Backdoor_MSIL_Gantorpe_A_2147652155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Gantorpe.A"
        threat_id = "2147652155"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gantorpe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Unique Bot.exe" ascii //weight: 1
        $x_1_2 = {55 6e 69 71 75 65 20 42 6f 74 [0-8] 4d 69 63 72 6f 73 6f 66 74 [0-8] 43 6f 70 79 72 69 67 68 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

