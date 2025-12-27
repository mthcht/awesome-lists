rule Ransom_MSIL_WormLocker_DA_2147771535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WormLocker.DA!MTB"
        threat_id = "2147771535"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WormLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WormLocker2.0" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "Worm_patch_Load" ascii //weight: 1
        $x_1_4 = "ransom_voice.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_WormLocker_DB_2147772924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WormLocker.DB!MTB"
        threat_id = "2147772924"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WormLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ransom_voice.vbs" ascii //weight: 1
        $x_1_2 = "get_CurrentDomain" ascii //weight: 1
        $x_1_3 = "WormLocker" ascii //weight: 1
        $x_1_4 = "cyberware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_WormLocker_DC_2147773123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WormLocker.DC!MTB"
        threat_id = "2147773123"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WormLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ransom_voice.vbs" ascii //weight: 1
        $x_1_2 = "WormLocker" ascii //weight: 1
        $x_1_3 = "worm_tool.sys" ascii //weight: 1
        $x_1_4 = "encrypted" ascii //weight: 1
        $x_1_5 = "DisableTaskMgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_WormLocker_DD_2147787836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WormLocker.DD!MTB"
        threat_id = "2147787836"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WormLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Worm Locker.exe" ascii //weight: 1
        $x_1_2 = "ToBase64String" ascii //weight: 1
        $x_1_3 = "ConfuserEx" ascii //weight: 1
        $x_1_4 = "Decompress" ascii //weight: 1
        $x_1_5 = "Decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_WormLocker_MX_2147920860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WormLocker.MX!MTB"
        threat_id = "2147920860"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WormLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "WormLocker" ascii //weight: 5
        $x_1_2 = "worm_tool.sys" wide //weight: 1
        $x_1_3 = "files have been encrypted" ascii //weight: 1
        $x_1_4 = "DisableTaskMgr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_WormLocker_AWM_2147939425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WormLocker.AWM!MTB"
        threat_id = "2147939425"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WormLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 09 2b 22 00 11 04 11 09 9a 28 ?? 00 00 0a 00 11 05 11 04 11 09 9a 11 06 6f ?? 00 00 06 00 00 11 09 17 58 13 09 11 09 11 04 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = "Worm_Locker\\obj\\Debug\\Worm_Locker.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_WormLocker_NKA_2147952495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WormLocker.NKA!MTB"
        threat_id = "2147952495"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WormLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SysWOW64.Script.ransom_voice.vbs" ascii //weight: 1
        $x_2_2 = "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE /v EnableBDEWithNoTPM /t REG_DWORD /d 1 /f" ascii //weight: 2
        $x_1_3 = "manage-bde -on C: -pw -rk C:\\key.bin" ascii //weight: 1
        $x_1_4 = "C:\\Windows\\System32\\WormLocker2.0.exe" ascii //weight: 1
        $x_1_5 = "/C reg add HKCU\\Environment /v windir /d \"cmd.exe /c start c:\\payload.exe" ascii //weight: 1
        $x_1_6 = ".encrypted" ascii //weight: 1
        $x_1_7 = "/C reagentc /disable && vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_8 = "9de7e59b-eb4f-4841-8726-3b10dd84c3c8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

