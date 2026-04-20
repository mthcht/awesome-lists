rule Ransom_MSIL_Werta_SK_2147967329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Werta.SK!MTB"
        threat_id = "2147967329"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Werta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WERTA-RANSOM-2024-KEY-256-BITS!!" ascii //weight: 1
        $x_1_2 = "WERTA_RANSOME.Properties.Resources" ascii //weight: 1
        $x_1_3 = "Ooops, your files have been encrypted!" ascii //weight: 1
        $x_1_4 = "Many of your documents, photos, videos, databases and other files are no longer accessible" ascii //weight: 1
        $x_1_5 = "DisableTaskMgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

