rule TrojanDropper_MSIL_Golbla_A_2147692123_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Golbla.A"
        threat_id = "2147692123"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Golbla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c reg add \"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /f /v shell /t REG_SZ /d explorer.exe,\"" wide //weight: 1
        $x_1_2 = ":Zone.Identifier" wide //weight: 1
        $x_1_3 = {53 54 41 52 54 55 50 5f 49 4e 46 4f 52 4d 41 54 49 4f 4e 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 69 64 5f 73 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_5 = "PolyBabyDecrypt" ascii //weight: 1
        $x_1_6 = "PE.dll" ascii //weight: 1
        $x_1_7 = {07 11 04 02 11 04 91 06 11 04 06 8e b7 5d 91 09 d6 20 ff 00 00 00 5f 61 b4 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

