rule Ransom_MSIL_HakunaMatata_SWL_2147925455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HakunaMatata.SWL!MTB"
        threat_id = "2147925455"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HakunaMatata"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Hakuna Matata 2.3" ascii //weight: 2
        $x_2_2 = "#ENCRYPT_EXTENSIONS" ascii //weight: 2
        $x_1_3 = "$d4d54c73-c442-4f8a-a94c-614cbe7282f3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HakunaMatata_PDZ_2147945076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HakunaMatata.PDZ!MTB"
        threat_id = "2147945076"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HakunaMatata"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "KILL_APPS_ENCRYPT_AGAIN" ascii //weight: 3
        $x_3_2 = "FULL_ENCRYPT" ascii //weight: 3
        $x_2_3 = "dataToEncrypt" ascii //weight: 2
        $x_2_4 = "TRIPLE_ENCRYPT" ascii //weight: 2
        $x_1_5 = "ALL_DRIVES" ascii //weight: 1
        $x_1_6 = "TARGETED_EXTENSIONS" ascii //weight: 1
        $x_1_7 = "CHANGE_PROCESS_NAME" ascii //weight: 1
        $x_1_8 = "<RECURSIVE_DIRECTORY_LOOK>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HakunaMatata_SMA_2147959986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HakunaMatata.SMA!MSR"
        threat_id = "2147959986"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HakunaMatata"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Hakuna Matata.exe" ascii //weight: 2
        $x_2_2 = "ENCRYPT FILES IN PROCESS" wide //weight: 2
        $x_2_3 = "DELETE SHADOW COPIES" wide //weight: 2
        $x_2_4 = "DISABLE RECOVERY MODE" wide //weight: 2
        $x_2_5 = "UAC BYPASS" wide //weight: 2
        $x_1_6 = "Readme.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

