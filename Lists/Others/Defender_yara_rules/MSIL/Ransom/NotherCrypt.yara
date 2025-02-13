rule Ransom_MSIL_NotherCrypt_PA_2147788299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/NotherCrypt.PA!MTB"
        threat_id = "2147788299"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NotherCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".onion.to/readme.php" wide //weight: 1
        $x_1_2 = "READ_ME.html" wide //weight: 1
        $x_1_3 = ".onion.to/data.php" wide //weight: 1
        $x_1_4 = "\\NOTHERSPACE_USE.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

