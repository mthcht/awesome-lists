rule Ransom_MSIL_Juwon_A_2147731693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Juwon.A!MTB"
        threat_id = "2147731693"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Juwon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jwransomeware_Load" ascii //weight: 1
        $x_1_2 = "juwonRansomeware.exe" ascii //weight: 1
        $x_1_3 = "juwonRansomeware.pdb" ascii //weight: 1
        $x_1_4 = "Sorry. The computer is encrypted by a military level algorithm by" wide //weight: 1
        $x_1_5 = "jw ransomware and can not be accessed. To recover, you must enter" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

