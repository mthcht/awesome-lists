rule Ransom_Win64_Encoder_KK_2147951396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Encoder.KK!MTB"
        threat_id = "2147951396"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {44 89 d0 99 f7 fe 48 63 d2 41 0f b6 04 14 42 30 04 13 49 83 c2 01 4c 39 d7 75}  //weight: 20, accuracy: High
        $x_10_2 = "files have been encrypted" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Encoder_MX_2147956810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Encoder.MX!MTB"
        threat_id = "2147956810"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Release\\Encoder AES+RSA.pdb" ascii //weight: 5
        $x_1_2 = "encryption.key" wide //weight: 1
        $x_1_3 = "CryptEncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Encoder_MX_2147956810_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Encoder.MX!MTB"
        threat_id = "2147956810"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted!" ascii //weight: 1
        $x_1_2 = "ransom.txt" ascii //weight: 1
        $x_1_3 = "key.bin" ascii //weight: 1
        $x_1_4 = "CryptEncrypt" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Encoder_MX_2147956810_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Encoder.MX!MTB"
        threat_id = "2147956810"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID" ascii //weight: 1
        $x_1_2 = "main.encryptFile" ascii //weight: 1
        $x_1_3 = "main.encryptDirectory" ascii //weight: 1
        $x_1_4 = "main.createRansomNote" ascii //weight: 1
        $x_1_5 = "To decrypt" ascii //weight: 1
        $x_1_6 = "Your files have been encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Encoder_AP_2147957855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Encoder.AP!AMTB"
        threat_id = "2147957855"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your system has been encrypted by WORDLEWARE." ascii //weight: 1
        $x_1_2 = "WORDLEWARE will begin decrypting your precious data!" ascii //weight: 1
        $x_1_3 = "You don't need to pay me to get your files back." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Encoder_GP_2147958501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Encoder.GP!AMTB"
        threat_id = "2147958501"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\IMPORTANT_README.txt" ascii //weight: 1
        $x_1_2 = "\\READ_FIRST.txt" ascii //weight: 1
        $x_1_3 = "recover@protonmail.com" ascii //weight: 1
        $x_1_4 = "C:\\Windows\\Temp\\cleanup.bat" ascii //weight: 1
        $x_1_5 = " 0.1 BTC " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Encoder_A_2147959270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Encoder.A!AMTB"
        threat_id = "2147959270"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Blackout Temporary Service" ascii //weight: 1
        $x_1_2 = "Blackout.File\\DefaultIcon" ascii //weight: 1
        $x_1_3 = "BlackoutMutex" ascii //weight: 1
        $x_1_4 = "C:\\Windows\\lock.png" ascii //weight: 1
        $x_1_5 = "BlackoutEncryptor" ascii //weight: 1
        $x_1_6 = "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v \"Shell\" /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Encoder_NE_2147959838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Encoder.NE!MTB"
        threat_id = "2147959838"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 f9 48 89 6c 24 40 45 31 c9 48 89 c3 4c 8d 44 24 60 31 d2 f3 0f 7e 05 a0 97 00 00 48 8d 05 19 96 00 00 c7 43 18 00 00 00 00 48 89 44 24 48 48 8d 05 25 96 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {c6 46 02 00 48 8d 5c 24 20 49 89 f0 48 8d 15 04 98 00 00 48 89 d9 48 8d ac 24 40 02 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\WINDOWS\\SYSTEM32\\recovery.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

