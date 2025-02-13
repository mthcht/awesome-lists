rule Ransom_MSIL_LockCrypt_PE_2147808947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockCrypt.PE!MTB"
        threat_id = "2147808947"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Scp-069$Lock" wide //weight: 1
        $x_1_2 = "\\$@!READ ME!@$.txt" wide //weight: 1
        $x_1_3 = "\\SCrypt.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

