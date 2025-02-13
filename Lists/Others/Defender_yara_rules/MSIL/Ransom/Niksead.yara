rule Ransom_MSIL_Niksead_2147725274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Niksead"
        threat_id = "2147725274"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Niksead"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DD5783BCF1E9002BC00AD5B83A95ED6E4EBB4AD5" ascii //weight: 2
        $x_2_2 = "Ransomware.exe" ascii //weight: 2
        $x_2_3 = "ftp://darl0ck.esy.es/logs/" wide //weight: 2
        $x_2_4 = "Files has been stollen" wide //weight: 2
        $x_2_5 = "\\Desktop\\READ_IT.txt" wide //weight: 2
        $x_2_6 = "C:\\Users\\d.koporushkin\\Desktop\\WindowsFormsApp1\\WindowsFormsApp1\\obj\\Debug\\Ransomware.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

