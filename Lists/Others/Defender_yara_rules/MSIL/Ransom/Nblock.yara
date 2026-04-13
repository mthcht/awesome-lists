rule Ransom_MSIL_Nblock_DAD_2147966872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Nblock.DAD!MTB"
        threat_id = "2147966872"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nblock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/c vssadmin.exe delete shadows /all /quiet" wide //weight: 2
        $x_2_2 = "ALL OF YOUR FILES ARE STOLEN AND ENCRYPTED" wide //weight: 2
        $x_2_3 = "Pay The ransom" wide //weight: 2
        $x_2_4 = "README_NBLOCK.txt" wide //weight: 2
        $x_1_5 = "locked.png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

