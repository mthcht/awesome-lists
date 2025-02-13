rule Ransom_MSIL_FileLock_A_2147729942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileLock.A"
        threat_id = "2147729942"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://2no.co/" wide //weight: 1
        $x_1_2 = "All your important files are encrypted!" wide //weight: 1
        $x_1_3 = "FilesL0cker RAN$OMWARE" wide //weight: 1
        $x_1_4 = "/c vssadmin.exe delete shadows /all /quiet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileLock_B_2147731405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileLock.B"
        threat_id = "2147731405"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$282b8d86-f33f-441e-8bb5-95903351be39" ascii //weight: 1
        $x_1_2 = "b03f5f7f11d50a3aPADPAD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

