rule Ransom_MSIL_GabutCrypt_PB_2147795844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/GabutCrypt.PB!MTB"
        threat_id = "2147795844"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GabutCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all /quiet & wmic shadowcopy delete" wide //weight: 1
        $x_1_2 = "wbadmin delete catalog -quiet" wide //weight: 1
        $x_1_3 = "your data has been locked" wide //weight: 1
        $x_1_4 = "gabuts project is back.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

