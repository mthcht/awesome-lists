rule Ransom_Win32_Amnesia_SK_2147759793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Amnesia.SK!MTB"
        threat_id = "2147759793"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Amnesia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "YOUR FILES ARE ENCRYPTED!" ascii //weight: 5
        $x_5_2 = "Administrator\\Application Data\\csrss.exe" ascii //weight: 5
        $x_5_3 = "cmd.exe /c bcdedit /set {default} bootstatuspolicy ignoreallfailuresh" ascii //weight: 5
        $x_5_4 = "HOW TO DECRYPT FILES.TXT" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Amnesia_MK_2147759810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Amnesia.MK!MTB"
        threat_id = "2147759810"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Amnesia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "C:\\ProgramData\\IDk.txt" ascii //weight: 5
        $x_5_2 = "C:\\ProgramData\\pubk.txt" ascii //weight: 5
        $x_10_3 = ".Sophos" ascii //weight: 10
        $x_2_4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 2
        $x_2_5 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 2
        $x_2_6 = "wbadmin delete catalog -quiet" ascii //weight: 2
        $x_10_7 = "Your Files Has Been Encrypted" ascii //weight: 10
        $n_100_8 = "vmss2core.exe" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Amnesia_MKV_2147853224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Amnesia.MKV!MTB"
        threat_id = "2147853224"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Amnesia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 89 45 e8 0f b6 84 9d e4 fb ff ff 8b 55 e8 8b 94 95 e4 fb ff ff 89 94 9d e4 fb ff ff 0f b6 c0 8b 55 e8 89 84 95 e4 fb ff ff 8b 84 9d e4 fb ff ff 8b 55 e8 03 84 95 e4 fb ff ff 25 ?? ?? ?? ?? 79 ?? 48 0d 00 ff ff ff 40 0f b6 84 85 e4 fb ff ff 8b 55 f0 30 04 32 46 ff 4d e4 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

