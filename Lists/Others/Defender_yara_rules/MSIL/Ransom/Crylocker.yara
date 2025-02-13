rule Ransom_MSIL_Crylocker_PAA_2147795711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crylocker.PAA!MTB"
        threat_id = "2147795711"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crylocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "View_encrypt_file_list" ascii //weight: 1
        $x_1_2 = "Encryption Complete" wide //weight: 1
        $x_1_3 = "strFileToEncrypt" ascii //weight: 1
        $x_1_4 = "DisableTaskMgr" wide //weight: 1
        $x_1_5 = ".Crylocker" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

