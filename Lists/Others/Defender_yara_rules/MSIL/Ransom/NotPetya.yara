rule Ransom_MSIL_NotPetya_SK_2147968600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/NotPetya.SK!MT"
        threat_id = "2147968600"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NotPetya"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".encrypted" ascii //weight: 1
        $x_1_2 = "!!! ALL YOUR FILES ARE ENCRYPTED !!!" ascii //weight: 1
        $x_1_3 = "C:\\Users\\Public\\!PLEASE_READ_ME!.txt" ascii //weight: 1
        $x_1_4 = "create NotPetya binpath= 'cmd /c C:\\Windows\\temp\\notpetya.exe'" ascii //weight: 1
        $x_1_5 = "start NotPetya" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

