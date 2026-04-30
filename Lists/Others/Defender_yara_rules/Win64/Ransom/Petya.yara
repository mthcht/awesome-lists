rule Ransom_Win64_Petya_MKV_2147947762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Petya.MKV!MTB"
        threat_id = "2147947762"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Petya"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your Files Have Been Encrypted" ascii //weight: 1
        $x_1_2 = "files on this computer have been encrypted using military-grade AES-256 encryption" ascii //weight: 1
        $x_1_3 = "Do not attempt to use third-party recovery tools" ascii //weight: 1
        $x_1_4 = "corrupt your files permanently" ascii //weight: 1
        $x_1_5 = "Contact us for decryption key" ascii //weight: 1
        $x_1_6 = "Do not shut down or modify this program" ascii //weight: 1
        $x_4_7 = "PetyaXWPF\\obj\\Release\\net8.0-windows\\win-x64\\PetyaX.pdb" ascii //weight: 4
        $x_1_8 = "Decryption complete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Petya_YBG_2147963336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Petya.YBG!MTB"
        threat_id = "2147963336"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Petya"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Petya MBR encryption" ascii //weight: 1
        $x_1_2 = "deleting encrypted files" ascii //weight: 1
        $x_1_3 = "README" ascii //weight: 1
        $x_1_4 = "files have been encrypted" ascii //weight: 1
        $x_1_5 = "encrypted MBR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Petya_ARA_2147968068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Petya.ARA!MTB"
        threat_id = "2147968068"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Petya"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f 11 54 24 20 4c 39 e3 73 32 49 8d 74 1d 00 48 8d 0c 1f 49 89 e8 0f 10 14 1f 48 89 f2 e8 ?? ?? ?? ?? 31 c0 8a 54 04 20 48 ff c0 30 16 48 ff c6 48 83 f8 10 75 ee 48 83 c3 10 eb c4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Petya_ARAC_2147968069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Petya.ARAC!MTB"
        threat_id = "2147968069"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Petya"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c8 99 41 f7 f8 48 63 d2 41 8a 04 12 30 04 31 48 ff c1 48 81 f9 10 01 00 00 75 e4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

