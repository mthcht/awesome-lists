rule Ransom_Win32_Lorenz_MAK_2147799136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lorenz.MAK!MTB"
        threat_id = "2147799136"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lorenz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 45 47 20 41 44 44 20 22 48 4b 45 59 5f 55 53 45 52 53 5c [0-5] 5c 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 44 65 73 6b 74 6f 70 22 20 2f 56 20 57 61 6c 6c 70 61 70 65 72 20 2f 54 20 52 45 47 5f 53 5a 20 2f 46 20 2f 44}  //weight: 1, accuracy: Low
        $x_1_2 = "CryptEncrypt" ascii //weight: 1
        $x_1_3 = "$Recycle.Bin" ascii //weight: 1
        $x_1_4 = "HELP_SECURITY_EVENT.html" ascii //weight: 1
        $x_1_5 = {68 74 74 70 3a 2f 2f 6c 6f 72 65 6e 7a [0-53] 2e 6f 6e 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Lorenz_TW_2147840657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lorenz.TW!MTB"
        threat_id = "2147840657"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lorenz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lorenz.sz40" ascii //weight: 1
        $x_1_2 = "SCHTASKS /run /TN sz401&SCHTASKS /Delete /TN sz401 /F" ascii //weight: 1
        $x_1_3 = "/PASSWORD:'crowen'" ascii //weight: 1
        $x_1_4 = "157.90.147.28" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Lorenz_HN_2147840658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lorenz.HN!MTB"
        threat_id = "2147840658"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lorenz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lorenzedzyzyjhzxvlcv347n" ascii //weight: 1
        $x_1_2 = "Your files are downloaded, encrypted, and currently unavailable. You can check it" ascii //weight: 1
        $x_1_3 = "162.33.179.45" wide //weight: 1
        $x_1_4 = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Lorenz_YAA_2147915965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lorenz.YAA!MTB"
        threat_id = "2147915965"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lorenz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ALL YOUR FILES ARE ENCRYPTED" ascii //weight: 5
        $x_1_2 = "recover your files is to get a decryptor" ascii //weight: 1
        $x_1_3 = "To get the decryptor" ascii //weight: 1
        $x_1_4 = "Do not rename files" ascii //weight: 1
        $x_1_5 = "Do not attempt to decrypt data using third party software" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

