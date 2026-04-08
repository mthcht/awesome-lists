rule Ransom_MSIL_Zusy_MK_2147966561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Zusy.MK!MTB"
        threat_id = "2147966561"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "README_NBLOCK.txt" ascii //weight: 5
        $x_3_2 = "All your files are locked with AES-256." ascii //weight: 3
        $x_2_3 = "key.bin - It is your only recovery tool." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

