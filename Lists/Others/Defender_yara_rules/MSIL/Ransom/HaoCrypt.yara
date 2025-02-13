rule Ransom_MSIL_HaoCrypt_PA_2147808896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HaoCrypt.PA!MTB"
        threat_id = "2147808896"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HaoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".hao17" wide //weight: 1
        $x_1_2 = "\\ransom.jpg" wide //weight: 1
        $x_1_3 = "\\Desktop\\README.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HaoCrypt_PB_2147809220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HaoCrypt.PB!MTB"
        threat_id = "2147809220"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HaoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "t.me/decovid19bot" wide //weight: 1
        $x_1_2 = "/C wmic csproduct get UUID" wide //weight: 1
        $x_1_3 = {46 69 6c 65 4c 6f 63 6b 65 72 2d 6d 61 73 74 65 72 5c [0-48] 5c 44 65 73 6b 31 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_4 = "Desk1.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

