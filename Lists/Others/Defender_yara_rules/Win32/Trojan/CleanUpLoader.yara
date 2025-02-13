rule Trojan_Win32_CleanUpLoader_DA_2147918699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CleanUpLoader.DA!MTB"
        threat_id = "2147918699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CleanUpLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CitizenApplicantsPermitsCamerasCarsFraud" ascii //weight: 1
        $x_1_2 = "AutomatedSuicide" ascii //weight: 1
        $x_1_3 = "Shadow Defender" ascii //weight: 1
        $x_1_4 = "Implementing" ascii //weight: 1
        $x_1_5 = "IsraelYields" ascii //weight: 1
        $x_1_6 = "ChemicalHandjobs" ascii //weight: 1
        $x_1_7 = "DiversityShoppercom" ascii //weight: 1
        $x_1_8 = "Copy Details To Clipboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CleanUpLoader_DB_2147919580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CleanUpLoader.DB!MTB"
        threat_id = "2147919580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CleanUpLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".bat & exit" ascii //weight: 1
        $x_1_2 = "WeaponSquirtFingeringPissRipeDiesel" ascii //weight: 1
        $x_1_3 = "CollectorsMillionsCargoMuseumsSlow" ascii //weight: 1
        $x_1_4 = "YesJapanAngleCgiTerrace" ascii //weight: 1
        $x_1_5 = "GotoReasonsJoshAppointedMastercardCalifornia" ascii //weight: 1
        $x_1_6 = "Basketball" ascii //weight: 1
        $x_1_7 = "LouisvilleCoach" ascii //weight: 1
        $x_1_8 = "Copy Details To Clipboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

