rule TrojanSpy_MSIL_Grieftylo_A_2147706073_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Grieftylo.A"
        threat_id = "2147706073"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Grieftylo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 74 65 61 6c 65 72 73 00 5f 68 6f 73 74 00 5f 75 73 65 72 6e 61 6d 65 00 5f 70 61 73 73 77 6f 72 64 00}  //weight: 1, accuracy: High
        $x_1_2 = "Infinity Logger" wide //weight: 1
        $x_1_3 = "after successful injection of your server." wide //weight: 1
        $x_1_4 = "L_0c: call void [mscorlib]System.IO.File::Copy(string, string)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

