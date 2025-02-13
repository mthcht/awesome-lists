rule Ransom_MSIL_Expboot_B_2147741045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Expboot.B"
        threat_id = "2147741045"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Expboot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your Files Are All Encrypted!" ascii //weight: 1
        $x_1_2 = "ExpBoot.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

