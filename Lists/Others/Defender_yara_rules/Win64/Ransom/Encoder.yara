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

rule Ransom_Win64_Encoder_NB_2147960207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Encoder.NB!MTB"
        threat_id = "2147960207"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 05 11 4c 11 00 48 01 d8 44 8b 00 45 85 c0 74 0d 48 8b 50 10 48 8b 48 08 4d 89 e9 ff d7}  //weight: 2, accuracy: High
        $x_1_2 = {8b 05 2e 4c 11 00 85 c0 0f 8e 51 fe ff ff 48 8b 3d 2b 66 11 00 31 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Encoder_PF_2147960382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Encoder.PF!MTB"
        threat_id = "2147960382"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BOT_CONNECTED" ascii //weight: 1
        $x_1_2 = "\\READ_ME.txt" wide //weight: 1
        $x_3_3 = "YOUR FILES ARE ENCRYPTED" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Encoder_PF_2147960382_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Encoder.PF!MTB"
        threat_id = "2147960382"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "### TH3 GR33N BL00D GR0UP  ###" ascii //weight: 3
        $x_1_2 = "ALL YOUR FILES HAVE BEEN ENCRYPTED!" ascii //weight: 1
        $x_1_3 = {46 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 3a 20 [0-16] 20 65 78 74 65 6e 73 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = "YOUR DATA IS NOW HELD FOR RANSOM" ascii //weight: 1
        $x_1_5 = "your network have been encrypted and penetrated by THE-GREEN-BLOOD-GROUP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_Encoder_NG_2147962193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Encoder.NG!MTB"
        threat_id = "2147962193"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 42 10 48 8b 0d ea 70 0f 00 8b 45 fc 48 63 d0 48 89 d0 48 c1 e0 02 48 01 d0 48 c1 e0 03 48 01 c8 49 89 c0 48 8b 55 d8 48 8b 45 c0 8b 4d f8 4d 89 c1 41 89 c8 48 89 c1 48 8b 05 b5 89 0f 00 ff d0}  //weight: 2, accuracy: High
        $x_1_2 = "!!!_READ_ME_IMPORTANT_!!!.txt" ascii //weight: 1
        $x_1_3 = "ALPHA_ENCRYPTED" ascii //weight: 1
        $x_1_4 = "taskkill /f /im explorer.exe" ascii //weight: 1
        $x_1_5 = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware" ascii //weight: 1
        $x_1_6 = "DisableRegistryTools" ascii //weight: 1
        $x_1_7 = "CYBER SECURITY LOCKDOWN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

