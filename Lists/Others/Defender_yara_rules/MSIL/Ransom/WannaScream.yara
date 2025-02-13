rule Ransom_MSIL_WannaScream_AYA_2147929768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WannaScream.AYA!MTB"
        threat_id = "2147929768"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WannaScream"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$3b87e3db-6c8e-4783-9247-ecf158a8d059" ascii //weight: 2
        $x_1_2 = "get_KeyDecrypt" ascii //weight: 1
        $x_1_3 = "DecryptionTool.Properties.Resources" ascii //weight: 1
        $x_1_4 = "get_Program_Main_Decryption_Tools" ascii //weight: 1
        $x_1_5 = "DecryptionTool.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

