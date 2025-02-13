rule Ransom_Win32_VoidCrypt_SK_2147753709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/VoidCrypt.SK!MTB"
        threat_id = "2147753709"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "VoidCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DECRPToffice@gmail.com" ascii //weight: 1
        $x_5_2 = "\\Decryption-Info.HTA" ascii //weight: 5
        $x_1_3 = "vssadmin delete shadows /all" ascii //weight: 1
        $x_1_4 = "D:\\yo\\chaos\\Release\\chaos.pdb" ascii //weight: 1
        $x_1_5 = "C:\\ProgramData\\pubkey.txt" ascii //weight: 1
        $x_1_6 = "C:\\ProgramData\\IDo.txt" ascii //weight: 1
        $x_1_7 = "netsh firewall set opmode mode=disable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_VoidCrypt_PA_2147767038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/VoidCrypt.PA!MTB"
        threat_id = "2147767038"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "VoidCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fuck" ascii //weight: 1
        $x_1_2 = "\\!INFO.HTA" wide //weight: 1
        $x_1_3 = "peace491@tuta.io" wide //weight: 1
        $x_1_4 = ".Peace" ascii //weight: 1
        $x_1_5 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 1
        $x_1_6 = "netsh firewall set opmode mode=disable" ascii //weight: 1
        $x_1_7 = "!!! Your Files Has Been Encrypted !!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_Win32_VoidCrypt_PAA_2147785235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/VoidCrypt.PAA!MTB"
        threat_id = "2147785235"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "VoidCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 10
        $x_10_2 = "fuckyoufuckyou" ascii //weight: 10
        $x_10_3 = "DisableTaskmgr" ascii //weight: 10
        $x_5_4 = "All Your Files Has Been Encrypted" wide //weight: 5
        $x_5_5 = "Decrypt-info.txt" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_VoidCrypt_PB_2147816454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/VoidCrypt.PB!MTB"
        threat_id = "2147816454"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "VoidCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Decrypt-me.txt" wide //weight: 1
        $x_1_2 = ".Sophos" ascii //weight: 1
        $x_1_3 = "wbadmin delete catalog -quiet" ascii //weight: 1
        $x_1_4 = "All Your Files Has Been Encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_VoidCrypt_PC_2147818151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/VoidCrypt.PC!MTB"
        threat_id = "2147818151"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "VoidCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Decrypt-info.txt" ascii //weight: 1
        $x_1_2 = "/voidcrypt/index.php" ascii //weight: 1
        $x_1_3 = "Fucking this country is forbidden" ascii //weight: 1
        $x_1_4 = "All your files are encrypted due to security problem with your computer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

