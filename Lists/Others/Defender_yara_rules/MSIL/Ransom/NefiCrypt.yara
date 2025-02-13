rule Ransom_MSIL_NefiCrypt_PI_2147751532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/NefiCrypt.PI!MSR"
        threat_id = "2147751532"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NefiCrypt"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NEFILIM-DECRYPT.txt" wide //weight: 1
        $x_1_2 = "fuk sosorin" ascii //weight: 1
        $x_1_3 = "hhow to fuck all the world" wide //weight: 1
        $x_1_4 = "\\NEFILIM.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

