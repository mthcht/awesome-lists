rule Trojan_MSIL_Anagra_R_2147830964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Anagra.R!MTB"
        threat_id = "2147830964"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Anagra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Task32Watch.pdb" ascii //weight: 1
        $x_1_2 = "Task32Watch.Fregat.resources" ascii //weight: 1
        $x_1_3 = "Shell Infrastructure Host" wide //weight: 1
        $x_1_4 = "DLL Host Service" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

