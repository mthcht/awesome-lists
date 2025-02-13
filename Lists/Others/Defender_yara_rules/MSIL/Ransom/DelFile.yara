rule Ransom_MSIL_DelFile_MA_2147838319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/DelFile.MA!MTB"
        threat_id = "2147838319"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DelFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Logs\\dbPurgeLog.txt" wide //weight: 1
        $x_1_2 = "Removing old file" wide //weight: 1
        $x_1_3 = "PersistDatabase" wide //weight: 1
        $x_1_4 = "Failed to stop Inventory Service. Aborting" wide //weight: 1
        $x_1_5 = "Software\\MYDATA automation AB\\Alpac" wide //weight: 1
        $x_1_6 = "843a9ce1-095e-4643-b03f-8030ee05766e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

