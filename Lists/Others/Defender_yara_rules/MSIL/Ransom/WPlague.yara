rule Ransom_MSIL_WPlague_DA_2147767268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WPlague.DA!MTB"
        threat_id = "2147767268"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WPlague"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR FILES GOT ENCRPTED" ascii //weight: 1
        $x_1_2 = "Ransomware2.0" ascii //weight: 1
        $x_1_3 = "Rasomware2._0.Ransomware2.resources" ascii //weight: 1
        $x_1_4 = "WannaPlaguE.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_WPlague_DB_2147767459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WPlague.DB!MTB"
        threat_id = "2147767459"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WPlague"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rasomware2.0" ascii //weight: 1
        $x_1_2 = "DECRYPT FILES" ascii //weight: 1
        $x_1_3 = "Rasomware2._0.Properties.Resources" ascii //weight: 1
        $x_1_4 = "only with our key we can recover your files" ascii //weight: 1
        $x_1_5 = "Now you need to contact bl4ack#1337 on the discord asking for the decrypt key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_WPlague_DC_2147767472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WPlague.DC!MTB"
        threat_id = "2147767472"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WPlague"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rasomware2.0" ascii //weight: 1
        $x_1_2 = "Ransomware2_Load" ascii //weight: 1
        $x_1_3 = "DisableTaskMgr" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
        $x_1_5 = "Rasomware2._0.Properties.Resources" ascii //weight: 1
        $x_1_6 = "Ransomware2._0.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_MSIL_WPlague_DD_2147767473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WPlague.DD!MTB"
        threat_id = "2147767473"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WPlague"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rasomware2.0" ascii //weight: 1
        $x_1_2 = "Pransomware" ascii //weight: 1
        $x_1_3 = "Pransomware_Load" ascii //weight: 1
        $x_1_4 = "Ransomware.Properties.Resources" ascii //weight: 1
        $x_1_5 = "files have been encrypted with special encryption program." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_WPlague_DE_2147780332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WPlague.DE!MTB"
        threat_id = "2147780332"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WPlague"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "FridayProject.Properties.Resources" ascii //weight: 5
        $x_5_2 = "DisableTaskMgr" ascii //weight: 5
        $x_5_3 = "DECRYPT FILES" ascii //weight: 5
        $x_1_4 = "FridayProject.0" ascii //weight: 1
        $x_1_5 = "Ransomware2.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_WPlague_DF_2147780432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WPlague.DF!MTB"
        threat_id = "2147780432"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WPlague"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "UHJvamVjdEZyaWRheSU=" ascii //weight: 5
        $x_5_2 = "ProjectFriday" ascii //weight: 5
        $x_5_3 = "FromBase64String" ascii //weight: 5
        $x_1_4 = "ZWM2MzJmZDktMTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTgx" ascii //weight: 1
        $x_1_5 = "CheckRemoteDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

