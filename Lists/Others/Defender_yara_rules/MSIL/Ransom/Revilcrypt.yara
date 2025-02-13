rule Ransom_MSIL_Revilcrypt_PAA_2147815608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Revilcrypt.PAA!MTB"
        threat_id = "2147815608"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Revilcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all /quiet && wmic shadowcopy delete" wide //weight: 1
        $x_1_2 = "VirusMSILNominatusStorm.pdb" ascii //weight: 1
        $x_1_3 = ".exe >>autorun.inf" wide //weight: 1
        $x_1_4 = "\\Kaspersky.exe" wide //weight: 1
        $x_1_5 = "Infector" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Revilcrypt_PAB_2147815685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Revilcrypt.PAB!MTB"
        threat_id = "2147815685"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Revilcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LockIT" ascii //weight: 1
        $x_1_2 = "EvilNominatusLocker" ascii //weight: 1
        $x_1_3 = "taskkill /im taskmgr.exe /f" wide //weight: 1
        $x_1_4 = "Oops your Computer Locked" ascii //weight: 1
        $x_1_5 = "bcdedit /delete {current}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

