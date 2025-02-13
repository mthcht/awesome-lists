rule Ransom_MSIL_Sapphire_DEA_2147756328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Sapphire.DEA!MTB"
        threat_id = "2147756328"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sapphire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sapphire Ransomware" ascii //weight: 1
        $x_1_2 = "\\Sapphire-Ransomware-master\\Sapphire Ransomware\\obj\\Debug\\" ascii //weight: 1
        $x_1_3 = ".VIVELAG" wide //weight: 1
        $x_1_4 = "RANSOMWARE #LAG" wide //weight: 1
        $x_1_5 = "052250058205075025075207820" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_Sapphire_DA_2147766032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Sapphire.DA!MTB"
        threat_id = "2147766032"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sapphire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sapphire Ransomware" ascii //weight: 1
        $x_1_2 = "_Encrypted$" ascii //weight: 1
        $x_1_3 = "ActionEncrypt" ascii //weight: 1
        $x_1_4 = "EncryptOrDecryptFile" ascii //weight: 1
        $x_1_5 = "GachaLife_Update.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Sapphire_DB_2147775311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Sapphire.DB!MTB"
        threat_id = "2147775311"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sapphire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sapphire Ransomware" ascii //weight: 1
        $x_1_2 = ".sapphire" ascii //weight: 1
        $x_1_3 = "DisableTaskMgr" ascii //weight: 1
        $x_1_4 = "Encryption Complete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

