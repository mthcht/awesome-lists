rule Ransom_MSIL_FileEncoder_2147789163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileEncoder!MTB"
        threat_id = "2147789163"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileEncoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_IV" ascii //weight: 1
        $x_1_2 = "set_IV" ascii //weight: 1
        $x_1_3 = "GenerateIV" ascii //weight: 1
        $x_1_4 = "get_ManagedThreadId" ascii //weight: 1
        $x_1_5 = "get_CurrentThread" ascii //weight: 1
        $x_1_6 = "Dequeue" ascii //weight: 1
        $x_1_7 = "Enqueue" ascii //weight: 1
        $x_1_8 = "System.Threading" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "ToBase64String" ascii //weight: 1
        $x_1_11 = "DownloadString" ascii //weight: 1
        $x_1_12 = "CreateDecryptor" ascii //weight: 1
        $x_1_13 = "CreateEncryptor" ascii //weight: 1
        $x_1_14 = "get_Key" ascii //weight: 1
        $x_1_15 = "set_Key" ascii //weight: 1
        $x_1_16 = "GenerateKey" ascii //weight: 1
        $x_1_17 = ".khonsari" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileEncoder_A_2147810231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileEncoder.A!MTB"
        threat_id = "2147810231"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileEncoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "ren C:\\Users\\%username%\\Downloads\\*.* *.*.Contrasenao" wide //weight: 1
        $x_1_3 = "ren C:\\Users\\%username%\\Pictures\\*.* *.*.Contrasena" wide //weight: 1
        $x_1_4 = "ren C:\\Users\\%username%\\Desktop\\*.*.Contrasena" wide //weight: 1
        $x_1_5 = "taskkill /f /im explorer.exe" wide //weight: 1
        $x_1_6 = "taskkill /f /im taskmgr.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

