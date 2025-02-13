rule Ransom_MSIL_Blocker_A_2147767706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Blocker.A!MTB"
        threat_id = "2147767706"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "export HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "WinDefender" ascii //weight: 1
        $x_1_3 = "Failed to set hook" ascii //weight: 1
        $x_1_4 = "StartupDelayInMSec" ascii //weight: 1
        $x_1_5 = "\\BLOCK\\obj\\Debug\\BLOCK.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Blocker_DA_2147768406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Blocker.DA!MTB"
        threat_id = "2147768406"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Black Hat Worm" ascii //weight: 1
        $x_1_2 = "W00ormSP.exe" ascii //weight: 1
        $x_1_3 = "ddosstop" ascii //weight: 1
        $x_1_4 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
        $x_1_5 = "black hat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Blocker_DA_2147768406_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Blocker.DA!MTB"
        threat_id = "2147768406"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "po0w0er0she0l0l" ascii //weight: 1
        $x_1_2 = "p!o!we!rs!he!ll!.e!xe" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 1
        $x_1_4 = "WindowsFormsApp" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Blocker_AB_2147846813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Blocker.AB!MTB"
        threat_id = "2147846813"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 2b f8 02 20 93 47 9a 75 28 ?? ?? ?? 06 06 73 1f 00 00 0a 06 6f ?? ?? ?? 0a 17 59 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 20 f8 47 9a 75 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 1b 2d 08 26 26 07 17 58 0b 2b 07 28 ?? ?? ?? 06 2b f3 07 1f 14 32 b7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Blocker_PADX_2147911301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Blocker.PADX!MTB"
        threat_id = "2147911301"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$31f0cbf9-41f7-45c2-9475-e149903ba80b" ascii //weight: 1
        $x_1_2 = "amogus.exe.Resource" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "mspaint.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Blocker_SPZM_2147911493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Blocker.SPZM!MTB"
        threat_id = "2147911493"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 13 11 1d 11 09 91 13 20 11 1d 11 09 11 ?? 11 ?? 61 11 1b 19 58 61 11 31 61 d2 9c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Blocker_SPGF_2147913751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Blocker.SPGF!MTB"
        threat_id = "2147913751"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 04 11 04 16 25 2d 1b 32 08 08 11 04 6f ?? 00 00 0a 09 18 58 0d 09 1c 2c fb 1c 2c f8 07 6f ?? 00 00 0a 32 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Blocker_SM_2147925860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Blocker.SM!MTB"
        threat_id = "2147925860"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 14 0a 73 03 00 00 0a 72 01 00 00 70 28 04 00 00 0a 6f 05 00 00 0a 0a 06 0b dd 0d 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

