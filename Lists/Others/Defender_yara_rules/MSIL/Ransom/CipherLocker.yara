rule Ransom_MSIL_CipherLocker_BSA_2147934015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CipherLocker.BSA!MTB"
        threat_id = "2147934015"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CipherLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "82"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "CipherLocker.exe" ascii //weight: 50
        $x_6_2 = "CipherLocker: Encrypti" ascii //weight: 6
        $x_4_3 = "on completed on" ascii //weight: 4
        $x_2_4 = "Attempting to encrypt:" ascii //weight: 2
        $x_2_5 = ".clocker" ascii //weight: 2
        $x_2_6 = "Disabled System Restore Points" ascii //weight: 2
        $x_2_7 = "System Restore disabled" ascii //weight: 2
        $x_2_8 = "vssadmin delete shadows" ascii //weight: 2
        $x_10_9 = "Your personal files have been encrypted by CipherLocker." ascii //weight: 10
        $x_15_10 = "CipherLocker.Ransomware+<ProcessFilesAsync>" ascii //weight: 15
        $x_15_11 = "CipherLocker.TelegramNotifier" ascii //weight: 15
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_15_*) and 1 of ($x_6_*) and 1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_50_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 4 of ($x_2_*))) or
            ((1 of ($x_50_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_50_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_50_*) and 1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((1 of ($x_50_*) and 2 of ($x_15_*) and 1 of ($x_2_*))) or
            ((1 of ($x_50_*) and 2 of ($x_15_*) and 1 of ($x_4_*))) or
            ((1 of ($x_50_*) and 2 of ($x_15_*) and 1 of ($x_6_*))) or
            ((1 of ($x_50_*) and 2 of ($x_15_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

