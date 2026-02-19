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

