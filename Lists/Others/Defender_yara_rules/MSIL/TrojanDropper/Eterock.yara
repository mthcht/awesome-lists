rule TrojanDropper_MSIL_Eterock_A_2147721502_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Eterock.A"
        threat_id = "2147721502"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Eterock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 78 70 6c 6f 69 74 73 00 6f 73 56 65 72 73 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_2 = {57 49 4e 38 5f 53 50 30 00 53 45 52 56 45 52 5f 32 4b 31 32 5f 53 50 30}  //weight: 1, accuracy: High
        $x_1_3 = "RunOnlyIfLoggedOn" ascii //weight: 1
        $x_1_4 = ".shadowbrokers.zip" ascii //weight: 1
        $x_1_5 = "EternalRocks.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

