rule Ransom_Win32_HiddenTear_A_2147714364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HiddenTear.A!!HiddenTear.gen!A"
        threat_id = "2147714364"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HiddenTear"
        severity = "Critical"
        info = "HiddenTear: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hidden_tear" ascii //weight: 1
        $x_1_2 = "HiddenTear" ascii //weight: 1
        $x_1_3 = "hidden-tear" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_HiddenTear_2147717148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HiddenTear.gen"
        threat_id = "2147717148"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HiddenTear"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hidden_tear" ascii //weight: 2
        $x_2_2 = "/hiddentear/" ascii //weight: 2
        $x_1_3 = "targetURL" ascii //weight: 1
        $x_1_4 = "encryptDirectory" ascii //weight: 1
        $x_1_5 = "SendPassword" ascii //weight: 1
        $x_1_6 = "startAction" ascii //weight: 1
        $x_1_7 = "bytesToBeEncrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_HiddenTear_SA_2147740796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HiddenTear.SA"
        threat_id = "2147740796"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HiddenTear"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "have been encrypted with Rush Ransomware" ascii //weight: 1
        $x_1_2 = "\\DECRYPT_YOUR_FILES.HTML" wide //weight: 1
        $x_1_3 = "\\Sanction Ransomware\\Project Encryptor\\hidden-tear" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_HiddenTear_PA_2147745622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HiddenTear.PA!MTB"
        threat_id = "2147745622"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stiyorsan Oku!!!.txt" wide //weight: 1
        $x_1_2 = "wallpaper.bmp" wide //weight: 1
        $x_1_3 = "---Oops Dosyalar" ascii //weight: 1
        $x_1_4 = "ifrelendi!---" ascii //weight: 1
        $x_1_5 = "saca 400 = Decryptor Kapi" ascii //weight: 1
        $x_1_6 = "Olan Decrypteri Sana Verecez" ascii //weight: 1
        $x_1_7 = "EncryptDirectory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_HiddenTear_GG_2147753784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HiddenTear.GG!MTB"
        threat_id = "2147753784"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RANSOMWARE" ascii //weight: 1
        $x_1_2 = "shadowcopy delete" ascii //weight: 1
        $x_1_3 = {59 4f 55 52 [0-4] 46 49 4c 45 53 [0-15] 45 4e 43 52 59 50 54 45 44}  //weight: 1, accuracy: Low
        $x_1_4 = "decryption" ascii //weight: 1
        $x_1_5 = "Bitcoin address" ascii //weight: 1
        $x_1_6 = "buy bitcoins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

