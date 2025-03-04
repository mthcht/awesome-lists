rule Ransom_Win32_MedusaLocker_PA_2147744349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MedusaLocker.PA!MTB"
        threat_id = "2147744349"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_2 = "bcdedit.exe /set {default} recoveryenabled No" wide //weight: 1
        $x_1_3 = "wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest" wide //weight: 1
        $x_1_4 = "[LOCKER XP] Kill processes" wide //weight: 1
        $x_1_5 = "Your files are encrypted, and currently unavailable." ascii //weight: 1
        $x_1_6 = "MedusaLocker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_MedusaLocker_PA_2147744349_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MedusaLocker.PA!MTB"
        threat_id = "2147744349"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your important files have been encrypted!" ascii //weight: 1
        $x_1_2 = "Your files are safe! Only modified" ascii //weight: 1
        $x_1_3 = "DO NOT MODIFY ENCRYPTED FILES" ascii //weight: 1
        $x_1_4 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_MedusaLocker_MK_2147763536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MedusaLocker.MK!MTB"
        threat_id = "2147763536"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_2 = "bcdedit.exe /set {default} recoveryenabled No" ascii //weight: 1
        $x_1_3 = "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_4 = "wbadmin DELETE SYSTEMSTATEBACKUP" ascii //weight: 1
        $x_1_5 = "wmic.exe SHADOWCOPY /nointeractive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_MedusaLocker_B_2147764776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MedusaLocker.B!MTB"
        threat_id = "2147764776"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\MedusaLockerInfo\\MedusaLockerProject\\MedusaLocker\\Release\\MedusaLocker.pdb" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Medusa" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\MDSLK" ascii //weight: 1
        $x_1_4 = "{8761ABBD-7F85-42EE-B272-A76179687C63}" ascii //weight: 1
        $x_1_5 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii //weight: 1
        $x_1_6 = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" ascii //weight: 1
        $x_1_7 = "vssadmin.exe delete" ascii //weight: 1
        $x_1_8 = "bcdedit.exe /set {default}" ascii //weight: 1
        $x_1_9 = "wbadmin delete systemstatebackup" ascii //weight: 1
        $x_1_10 = ".exe,.dll,.sys,.ini,.lnk,.rdp,.encrypted" ascii //weight: 1
        $x_1_11 = "[LOCKER]" ascii //weight: 1
        $x_1_12 = "SOFTWARE\\akocfg" ascii //weight: 1
        $x_1_13 = "wmic.exe SHADOWCOPY /nointeractive" ascii //weight: 1
        $x_1_14 = "YOUR COMPANY NETWORK HAS BEEN PENETRATED" ascii //weight: 1
        $x_1_15 = "ALL YOUR IMPORTANT FILES HAVE BEEN ENCRYPTED!" ascii //weight: 1
        $x_1_16 = "Recovery_Instructions.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_Win32_MedusaLocker_DA_2147767271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MedusaLocker.DA!MTB"
        threat_id = "2147767271"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 8d 1c ff ff ff 83 c1 ?? 89 8d ?? ?? ?? ?? 8b 95 01 3b 95 ?? ?? ?? ?? 74 37 8b 85 01 50 8d 8d ?? ?? ?? ?? e8 50 1c 00 00 8d 8d ?? ?? ?? ?? 51 e8 34 b6 ff ff 83 c4 04 50 8d 4d fb e8 18 86 01 00 8d 8d ?? ?? ?? ?? e8 8d 19 00 00 eb ac}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_MedusaLocker_PB_2147845497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MedusaLocker.PB!MTB"
        threat_id = "2147845497"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".SOFTWARE\\PAIDMEMES" wide //weight: 1
        $x_1_2 = "PUTINHUILO1337" ascii //weight: 1
        $x_1_3 = {33 d2 8b c1 f7 75 ?? 8a 04 31 81 c2 ?? ?? ?? ?? 32 02 8b 55 ?? 88 04 11 41 8b 75 ?? 3b cf 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_MedusaLocker_AA_2147893941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MedusaLocker.AA!MTB"
        threat_id = "2147893941"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Medusa\\Release\\gaze.pdb" ascii //weight: 1
        $x_1_2 = "We have PENETRATE your network and COPIED data" ascii //weight: 1
        $x_1_3 = "We have ENCRYPTED some your files" ascii //weight: 1
        $x_1_4 = "MEDUSA DECRYPTOR and DECRYPTION KEYs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_MedusaLocker_AA_2147893941_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MedusaLocker.AA!MTB"
        threat_id = "2147893941"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\$Windows" wide //weight: 1
        $x_1_2 = ":\\$WinREAgent\\" wide //weight: 1
        $x_1_3 = "[+][Encrypt] Encrypted:" wide //weight: 1
        $x_1_4 = "taskkill /f /im explorer.exe" wide //weight: 1
        $x_1_5 = "rem kill" wide //weight: 1
        $x_1_6 = "-shares=" wide //weight: 1
        $x_1_7 = "stub_win_x64_encrypter.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_MedusaLocker_PC_2147899806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MedusaLocker.PC!MTB"
        threat_id = "2147899806"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PUTINHUILO1337" ascii //weight: 1
        $x_1_2 = {8b c6 8a 0c 31 33 d2 f7 75 ?? 8b 45 ?? 32 8a ?? ?? ?? ?? 88 0c 30 46 8b 4d ?? 3b f7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_MedusaLocker_PD_2147900657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MedusaLocker.PD!MTB"
        threat_id = "2147900657"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOHOL1488" wide //weight: 1
        $x_1_2 = "PUTINHUILO1337" ascii //weight: 1
        $x_1_3 = "EncryptedExtension" ascii //weight: 1
        $x_1_4 = "Start encryption.." wide //weight: 1
        $x_1_5 = "EncryptedExtension\": \".LATCHNETWORK3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

