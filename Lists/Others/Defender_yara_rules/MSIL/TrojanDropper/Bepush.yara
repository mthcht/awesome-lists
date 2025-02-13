rule TrojanDropper_MSIL_Bepush_D_2147682902_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Bepush.D"
        threat_id = "2147682902"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bepush"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 45 6d 72 65 5c 44 65 73 6b 74 6f 70 5c 44 6f 77 6e 6c 6f 61 64 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 6c 69 63 61 74 69 6f 6e 35 5c 6f 62 6a 5c 44 65 62 75 67 5c 46 6c 61 73 68 47 75 6e 63 65 6c 6c 65 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {6f 72 6d 73 41 70 70 6c 69 63 61 74 69 6f 6e 35 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 00 46 6c 61 73 68 47 75 6e 63 65 6c 6c 65 2e 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_Bepush_2147684891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Bepush"
        threat_id = "2147684891"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bepush"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\SExtension" ascii //weight: 1
        $x_1_2 = "\\VExtension" ascii //weight: 1
        $x_1_3 = "YokExe.exe" ascii //weight: 1
        $x_1_4 = "FLVGuncelle" ascii //weight: 1
        $x_1_5 = "FlashGuncelle" ascii //weight: 1
        $x_1_6 = "BakBakim" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_MSIL_Bepush_C_2147685041_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Bepush.C"
        threat_id = "2147685041"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bepush"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\SExtension" ascii //weight: 1
        $x_1_2 = "YokExe.exe" ascii //weight: 1
        $x_1_3 = "/extFiles/control" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_Bepush_C_2147685041_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Bepush.C"
        threat_id = "2147685041"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bepush"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\VExtension" ascii //weight: 1
        $x_1_2 = "YokExe.exe" ascii //weight: 1
        $x_1_3 = "/extFiles/control" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_Bepush_C_2147685041_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Bepush.C"
        threat_id = "2147685041"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bepush"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Flash Update" ascii //weight: 1
        $x_1_2 = "\\SExtension" ascii //weight: 1
        $x_1_3 = "YokExe.exe" ascii //weight: 1
        $x_1_4 = "Facebook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

