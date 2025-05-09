rule Ransom_Win32_CONTI_DA_2147768354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CONTI.DA!MTB"
        threat_id = "2147768354"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CONTI"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All of your files are currently encrypted by CONTI strain" ascii //weight: 1
        $x_1_2 = "YOU SHOULD BE AWARE!" ascii //weight: 1
        $x_1_3 = ".onion" ascii //weight: 1
        $x_1_4 = "https://contirecovery.info" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_CONTI_DA_2147768354_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CONTI.DA!MTB"
        threat_id = "2147768354"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CONTI"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "199"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "deathofreg" ascii //weight: 100
        $x_50_2 = "cleaner_.log" ascii //weight: 50
        $x_20_3 = "Destroying bootloader" ascii //weight: 20
        $x_20_4 = "Destroying system files" ascii //weight: 20
        $x_1_5 = "net stop winlogon" ascii //weight: 1
        $x_1_6 = "net stop lsass" ascii //weight: 1
        $x_1_7 = "net stop services" ascii //weight: 1
        $x_1_8 = "net stop spooler" ascii //weight: 1
        $x_1_9 = "net stop rpcss" ascii //weight: 1
        $x_1_10 = "net stop WinREAgent" ascii //weight: 1
        $x_1_11 = "net stop RecoveryAgent" ascii //weight: 1
        $x_1_12 = "net stop RecoveryService" ascii //weight: 1
        $x_1_13 = "net stop wininit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_CONTI_DC_2147771290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CONTI.DC!MTB"
        threat_id = "2147771290"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CONTI"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "contirecovery" ascii //weight: 1
        $x_1_2 = "YOU SHOULD BE AWARE!" ascii //weight: 1
        $x_1_3 = ".onion" ascii //weight: 1
        $x_1_4 = "---BEGIN ID---" ascii //weight: 1
        $x_1_5 = "TOR VERSION :" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

