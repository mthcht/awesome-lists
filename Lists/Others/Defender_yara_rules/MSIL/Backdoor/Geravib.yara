rule Backdoor_MSIL_Geravib_A_2147717150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Geravib.A"
        threat_id = "2147717150"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Geravib"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VB-RAT-Client" ascii //weight: 1
        $x_1_2 = "UploadScreenshot" ascii //weight: 1
        $x_1_3 = "MeineVictimID" ascii //weight: 1
        $x_1_4 = "Dateiuploaden" ascii //weight: 1
        $x_1_5 = "ProzessListe" wide //weight: 1
        $x_1_6 = "Inhalteauflisten" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_MSIL_Geravib_B_2147739768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Geravib.B!bit"
        threat_id = "2147739768"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Geravib"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "K.L Carder" ascii //weight: 3
        $x_2_2 = "Reversa 2.0" ascii //weight: 2
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "Muda" wide //weight: 1
        $x_1_5 = "Imagem" wide //weight: 1
        $x_1_6 = "UploadScreenshot" ascii //weight: 1
        $x_2_7 = "\\svchost.il" wide //weight: 2
        $x_1_8 = "<PAGSEGURO> Usuario: " wide //weight: 1
        $x_3_9 = "svchost.kwreT_dsiwe_er" wide //weight: 3
        $x_2_10 = "AntiTaskManagerKill::CheckRun" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

