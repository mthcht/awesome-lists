rule Trojan_Win64_Filecoder_TR_2147835525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filecoder.TR!MTB"
        threat_id = "2147835525"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 33 b9 18 00 00 00 48 8b 43 18 48 39 43 10 48 0f 42 cd 48 8b 53 20 48 85 d2 74 14 48 8b fa 33 c0 48 8b 0c 19 f3 aa 48 8b ca e8 10 1b ff ff 90 ba 38 00 00 00 48 8b cb e8 82 9a 00 00 48 8b de 48 85 f6 75 ba}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Filecoder_ARA_2147903289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filecoder.ARA!MTB"
        threat_id = "2147903289"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 c0 41 ff c0 6b c8 11 88 4c 14 30 48 ff c2 48 83 fa 10 7c d9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Filecoder_PAP_2147917354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filecoder.PAP!MTB"
        threat_id = "2147917354"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "rename each file after encrypted" wide //weight: 2
        $x_1_2 = "start encrypting hardisks/USBs" wide //weight: 1
        $x_1_3 = "shutdown machine after encryption" wide //weight: 1
        $x_1_4 = "log encrypted files" wide //weight: 1
        $x_1_5 = "put your email address" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Filecoder_PAZ_2147917931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filecoder.PAZ!MTB"
        threat_id = "2147917931"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your files have been fucked" ascii //weight: 2
        $x_2_2 = "you will get your files back" ascii //weight: 2
        $x_1_3 = "\\README.txt" ascii //weight: 1
        $x_1_4 = "\\Windows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Filecoder_BA_2147932266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filecoder.BA!MTB"
        threat_id = "2147932266"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Greetings from Cs-137 Group" ascii //weight: 1
        $x_1_2 = "Your files have been encrypted with ChaCha20" ascii //weight: 1
        $x_1_3 = "The encryption key was randomly generated and not saved because this is development version" ascii //weight: 1
        $x_1_4 = "This means your files cannot be recovered" ascii //weight: 1
        $x_1_5 = "Go away security research,," ascii //weight: 1
        $x_1_6 = "ussadmin.exe celete shadows /all" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Filecoder_SCR_2147936586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filecoder.SCR!MTB"
        threat_id = "2147936586"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 c9 49 89 e9 c4 e1 f9 6e c8 48 8b 84 24 10 04 00 00 4c 8d 05 c3 02 00 00 c4 e3 f1 22 84 24 08 04 00 00 01 48 89 45 10 c5 fa 7f 45 00 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 15 90 ab 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Filecoder_QZ_2147937595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filecoder.QZ!MTB"
        threat_id = "2147937595"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "h1:LYDUdQBzWPgCOuwoGl3qPECiKXwqE0+tA9JM1kvIpfw=" ascii //weight: 2
        $x_2_2 = "main.setWallpaper" ascii //weight: 2
        $x_2_3 = "Prince-Ransomware/filewalker.EncryptDirectory" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Filecoder_PGF_2147942477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filecoder.PGF!MTB"
        threat_id = "2147942477"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vssadmin delete shadows /all /quiet >nul" ascii //weight: 2
        $x_2_2 = "wbadmin delete catalog -quiet >nul" ascii //weight: 2
        $x_2_3 = "bcdedit /set {default} recoveryenabled no >nul" ascii //weight: 2
        $x_2_4 = "svchost_log.txt" ascii //weight: 2
        $x_2_5 = "files encrypted. Check README" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Filecoder_NIA_2147947157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filecoder.NIA!MTB"
        threat_id = "2147947157"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".ENCRYPT" ascii //weight: 2
        $x_1_2 = "Ooops, your files have been encrypted!" ascii //weight: 1
        $x_1_3 = "Send $1000 worth of Monero to this address" ascii //weight: 1
        $x_1_4 = "Your files will be lost on" ascii //weight: 1
        $x_1_5 = "RansomWindowClass" ascii //weight: 1
        $x_1_6 = "Encrypted Key:" ascii //weight: 1
        $x_1_7 = "Decryption Key:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Filecoder_AFD_2147948247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filecoder.AFD!MTB"
        threat_id = "2147948247"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {80 33 aa 48 39 c2 74 14 0f 1f 40 00 80 32 aa 80 72 01 aa 48 83 c2 02 48 39 c2}  //weight: 3, accuracy: High
        $x_2_2 = "program files\\vmware\\vmware tools\\vmtoolsd.exe" ascii //weight: 2
        $x_1_3 = "program files\\oracle\\virtualbox guest additions\\vboxservice.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Filecoder_SXC_2147949753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filecoder.SXC!MTB"
        threat_id = "2147949753"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8d 95 80 0b 00 00 48 8d 85 58 15 00 00 48 89 c1 e8 ?? ?? ?? ?? 89 c2 8b 85 4c 18 00 00 48 98 88 94 05 ?? ?? ?? ?? 83 85 4c 18 00 00}  //weight: 3, accuracy: Low
        $x_2_2 = {0f b6 94 05 60 15 00 00 44 8b 85 48 18 00 00 48 8b 85 10 18 00 00 4c 01 c0 31 ca 88 10 83 85 48 18 00 00 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Filecoder_SXD_2147951864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filecoder.SXD!MTB"
        threat_id = "2147951864"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {49 ff cc 4c 89 64 24 ?? 4c 8b 6c 24 ?? 4c 89 e0 48 c1 e0 05 49 8b 7c 05 00 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 39 cf 0f 84}  //weight: 3, accuracy: Low
        $x_2_2 = {4c 89 e9 48 c1 e1 ?? 4c 89 24 08 48 89 5c 08 08 48 8d 94 24 ?? ?? ?? ?? f3 0f 6f 02 f3 0f 7f 44 08 10 49 ff c5 4c 89 6c 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

