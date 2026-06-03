rule Ransom_MSIL_LiberlyCrypt_DA_2147970832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LiberlyCrypt.DA!MTB"
        threat_id = "2147970832"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LiberlyCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bcdedit /set {default} recoveryenabled No" ascii //weight: 1
        $x_1_2 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_3 = "schtasks /delete /tn \"LiberlyUpdate\" /f" ascii //weight: 1
        $x_10_4 = "L1b3rly_" ascii //weight: 10
        $x_1_5 = "LbrExfil_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_LiberlyCrypt_AMTB_2147970838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LiberlyCrypt!AMTB"
        threat_id = "2147970838"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LiberlyCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CrawlAndEncrypt" ascii //weight: 1
        $x_2_2 = "@Reis_liberly" ascii //weight: 2
        $x_2_3 = "Booting LiberlyOS" ascii //weight: 2
        $x_1_4 = "KillExplorerOldSchool" ascii //weight: 1
        $x_1_5 = "LiberlyCryptMutex" ascii //weight: 1
        $x_2_6 = "LiberlyGUI" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

