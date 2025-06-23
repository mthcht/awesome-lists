rule Ransom_MSIL_TankRansom_SK_2147944110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/TankRansom.SK!MTB"
        threat_id = "2147944110"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TankRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".TANKIX" ascii //weight: 1
        $x_1_2 = "All your computer files has been encrypted with a special algorithm by Tanki X. Your documents, photos, music, etc" ascii //weight: 1
        $x_1_3 = "C:\\Windows\\BSOD.exe" ascii //weight: 1
        $x_1_4 = "TankRansom_3._0.Properties.Resources" ascii //weight: 1
        $x_1_5 = "C:/Windows/Warning.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_TankRansom_SL_2147944227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/TankRansom.SL!MTB"
        threat_id = "2147944227"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TankRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Tanki X Ransomware 4.0" ascii //weight: 2
        $x_2_2 = "Attention! Your OS and your files is encrypted by Tanki X Ransomware" ascii //weight: 2
        $x_2_3 = "$6761fd97-2c9b-4fb1-ac6c-ca1323207e7a" ascii //weight: 2
        $x_2_4 = "ArhibotTankiXLarny1337" ascii //weight: 2
        $x_2_5 = "/k taskkill /f /im AvastUI.exe && exit" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_TankRansom_SM_2147944391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/TankRansom.SM!MTB"
        threat_id = "2147944391"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TankRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TankiXRansomware.Properties.Resources.resources" ascii //weight: 2
        $x_2_2 = "$ccedb98b-bcbb-4adb-b5da-a8086981c6e9" ascii //weight: 2
        $x_2_3 = "TankiXRansomware\\obj\\Debug\\TankiXRansomware.pdb" ascii //weight: 2
        $x_2_4 = "Welcome! Your all files, and data is FULLY ENCRYPTED with a special algoritm TX!" ascii //weight: 2
        $x_2_5 = "Don't try to kill ransomware - Your PC will burn" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

