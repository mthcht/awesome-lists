rule Ransom_Win32_FileCoder_A_2147740179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.A!MTB"
        threat_id = "2147740179"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Do not shutdown your computer or try to close this program: All your personnal data will be deleted !" ascii //weight: 1
        $x_1_2 = "49H8Kbf15JFN2diG5evGHA5G49qhgFBuDid86z3MKxTv59dcqySCzFWUL3SgsEk2SufzTziHp3UE5P8BatwuyFuv1bBKQw2" ascii //weight: 1
        $x_1_3 = "Most of your data has been encrypted by AES 256" ascii //weight: 1
        $x_1_4 = "send us $ 300 in Monero sent to the address you can see below" ascii //weight: 1
        $x_1_5 = "You can get monero here : https://localmonero.co/" ascii //weight: 1
        $x_1_6 = "\\GG-Ransomware-master\\GG ransomware\\GG ransomware\\obj\\Debug\\Ransom.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_FileCoder_B_2147742539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.B"
        threat_id = "2147742539"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your file will be unlocked automaticlly" ascii //weight: 1
        $x_1_2 = "\\\\.\\pipe\\UxdEvent_API_Service" ascii //weight: 1
        $x_1_3 = "http://10.103.2.247" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_PC_2147745424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.PC!MTB"
        threat_id = "2147745424"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransomware/RansomwareController" wide //weight: 1
        $x_1_2 = "Your files were encrypted." wide //weight: 1
        $x_1_3 = "SPI_SETDESKWALLPAPER" ascii //weight: 1
        $x_1_4 = "DownloadRemoteImageFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_PC_2147745424_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.PC!MTB"
        threat_id = "2147745424"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 89 f9 81 c1 35 1b 00 00 66 89 cb 8b 4c 24 ?? 66 89 5c 24 ?? 8a 84 01 ?? ?? ?? ?? 88 44 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 0f b6 0c 0a 66 89 7c 24 ?? 0f b6 54 24 ?? 29 d1 88 c8 88 44 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 09 c9 09 d2 8b 74 24 ?? 89 54 24 ?? 89 4c 24 ?? 8b 4c 24 ?? 88 04 31 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_PD_2147747860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.PD!MTB"
        threat_id = "2147747860"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\Readme.README" wide //weight: 1
        $x_1_2 = "Every byte on any types of your devices was encrypted." ascii //weight: 1
        $x_1_3 = "Don't try to use backups because it were encrypted too." ascii //weight: 1
        $x_1_4 = ".pysa" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_PD_2147747860_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.PD!MTB"
        threat_id = "2147747860"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "UP\\ulog.txt" wide //weight: 1
        $x_1_2 = "Removed.." wide //weight: 1
        $x_1_3 = ".decrypted" wide //weight: 1
        $x_1_4 = "UPirate.exe" wide //weight: 1
        $x_1_5 = {5c 55 50 69 72 61 74 65 5c 55 50 69 72 61 74 65 5c [0-32] 5c 55 50 69 72 61 74 65 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_FileCoder_PE_2147749663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.PE!MTB"
        threat_id = "2147749663"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[RansomPC]" wide //weight: 1
        $x_1_2 = "[RansomEncryptFiles]" wide //weight: 1
        $x_1_3 = "[RansomScreenshot]" wide //weight: 1
        $x_1_4 = "[RansomWarningMSGBody]" wide //weight: 1
        $x_1_5 = ".encrypted" wide //weight: 1
        $x_1_6 = "RansomRATClient" ascii //weight: 1
        $x_1_7 = "EncryptDesktopFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_PE_2147749663_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.PE!MTB"
        threat_id = "2147749663"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "README.txt" ascii //weight: 1
        $x_1_2 = "Some files in your computer have been encrypted!" ascii //weight: 1
        $x_1_3 = "power@ransomware.com" ascii //weight: 1
        $x_1_4 = {5c 50 6f 77 65 72 52 61 6e 73 6f 6d 5c [0-16] 5c 50 6f 77 65 72 52 61 6e 73 6f 6d 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_AF_2147752751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.AF!MSR"
        threat_id = "2147752751"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "README.txt" ascii //weight: 2
        $x_1_2 = "Sorry, but your files are locked due to a critical error in your system" ascii //weight: 1
        $x_1_3 = "You have to pay BITCOINS to get your file decoder" ascii //weight: 1
        $x_2_4 = "Fuck_this_PC" ascii //weight: 2
        $x_10_5 = "http://restore-now.top/online-chat" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_MK_2147754283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.MK!MSR"
        threat_id = "2147754283"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c timeout 1 && del \"%s\"" ascii //weight: 1
        $x_2_2 = "ReadMe.txt" ascii //weight: 2
        $x_4_3 = "All your data been crypted" ascii //weight: 4
        $x_2_4 = "{KEY11111}" ascii //weight: 2
        $x_2_5 = "sodinsupport@cock.li" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_YX_2147754348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.YX!MTB"
        threat_id = "2147754348"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your data been crypted" wide //weight: 1
        $x_1_2 = "Use mail to contact" wide //weight: 1
        $x_1_3 = "\\tor.exe" wide //weight: 1
        $x_1_4 = ".onion" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_NC_2147754375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.NC!MTB"
        threat_id = "2147754375"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shutdown -s -f -t" ascii //weight: 1
        $x_1_2 = "\\Desktop\\README.txt" ascii //weight: 1
        $x_1_3 = "\\Ransomware.pdb" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_B_2147755771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.B!MTB"
        threat_id = "2147755771"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your personal files are being deleted. Your photos, videos, documents, etc" ascii //weight: 1
        $x_1_2 = "I want to play a game with you.., however, let me explain the golden RULES" ascii //weight: 1
        $x_1_3 = "But, don't worry! It will only happen if you don't comply" ascii //weight: 1
        $x_1_4 = "However, I've already encrypted your personal files, so you cannot access them." ascii //weight: 1
        $x_1_5 = "By the way, I hope you don't keep nudes' photos and videos or illegal business" ascii //weight: 1
        $x_1_6 = "should you restart the computer, Game Over!!!, you lose" ascii //weight: 1
        $x_1_7 = "Wasting your key entries will just cause permanent data damage to your computer" ascii //weight: 1
        $x_1_8 = "Great job, I'm decrypting your files" ascii //weight: 1
        $x_1_9 = "Encrypted_FileList.txt" ascii //weight: 1
        $x_1_10 = "\\Release\\Coco2020.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_Win32_FileCoder_C_2147755772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.C!MTB"
        threat_id = "2147755772"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Decrypt Instructions.txt" ascii //weight: 1
        $x_1_2 = "All of your files are encrypted, to decrypt them write us to email:" ascii //weight: 1
        $x_1_3 = "delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "Decryption Key:" ascii //weight: 1
        $x_1_5 = "\\Release\\ParaEncrypt.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_FileCoder_D_2147756376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.D!MTB"
        threat_id = "2147756376"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransomeware.My.Resources" ascii //weight: 1
        $x_1_2 = "Bitcoins" ascii //weight: 1
        $x_1_3 = "Decryption Key" ascii //weight: 1
        $x_1_4 = "loader-gif-300-spinner-" wide //weight: 1
        $x_1_5 = "/C choice /C Y /N /D Y /T" wide //weight: 1
        $x_1_6 = "Ransomeware.pdb" ascii //weight: 1
        $x_1_7 = "LOST all your files" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_FileCoder_D_2147756376_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.D!MTB"
        threat_id = "2147756376"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "We are so sorry... Your files were encrypted!" ascii //weight: 1
        $x_1_2 = "/c vSSAdmiN dELeTe ShaDowS /AlL /qUieT" ascii //weight: 1
        $x_1_3 = "%fileid%-DECRYPT.txt" ascii //weight: 1
        $x_1_4 = "g-DECRYPT.txt" ascii //weight: 1
        $x_1_5 = "\"ip\":\"%ip%\",\"country\":\"%cnt%\",\"version\":\"%ver%\",\"computer_name\":\"%compname%\",\"username\":\"%user%\",\"os\":\"%win%\",\"pr_key\":" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_FileCoder_TX_2147758416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.TX!MSR"
        threat_id = "2147758416"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!TXDOT_READ_ME!.txt" ascii //weight: 1
        $x_1_2 = "Your files are securely ENCRYPTED" ascii //weight: 1
        $x_1_3 = "Mail us: txdot911@protonmail.com" ascii //weight: 1
        $x_1_4 = "set {default} recoveryenabled no" ascii //weight: 1
        $x_1_5 = "Change /TN \"\\Microsoft\\Windows\\SystemRestore\\SR\" /disable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_GI_2147758516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.GI!MTB"
        threat_id = "2147758516"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 94 01 2d ad 00 00 2b 95 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 01 a1 01 2d 2d ad 00 00 a3 01 8b 0d ?? ?? ?? ?? 03 8d 00 03}  //weight: 2, accuracy: Low
        $x_2_2 = {54 68 70 69 20 70 3b 75 67 72 28 73 20 63 38 74 6e 6f 45 3e 62 65 69 68 75 6e 69 6f 6e 20 [0-3] 54 53 20 2c 75 64 65}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_CH_2147758819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.CH!MTB"
        threat_id = "2147758819"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "csrsse.exe" ascii //weight: 1
        $x_1_2 = "52pojie-DECRYPT" ascii //weight: 1
        $x_1_3 = ".52pojie" ascii //weight: 1
        $x_1_4 = "Qkkbal" ascii //weight: 1
        $x_1_5 = "\\shell\\open\\command" ascii //weight: 1
        $x_1_6 = "_EL_HideOwner" ascii //weight: 1
        $x_1_7 = "(*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR|JPG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_Win32_FileCoder_M_2147759421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.M!MTB"
        threat_id = "2147759421"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 2c e4 09 c5 83 e7 00 31 ef 5d 6a 00 89 14 e4 31 d2 31 fa 89 93 ?? ?? ?? ?? 5a 89 45 fc 2b 45 fc 0b 83 ?? ?? ?? ?? 83 e6 00 31 c6 8b 45 fc 89 7d f8 29 ff 0b bb ?? ?? ?? ?? 89 f9 8b 7d f8 fc f3 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_M_2147759421_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.M!MTB"
        threat_id = "2147759421"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /delete /tn WM /F" ascii //weight: 1
        $x_1_2 = "Recovery your files" ascii //weight: 1
        $x_1_3 = "I am so sorry ! All your files have been encryptd by RSA-1024 and AES-256 due to a computer security problems" ascii //weight: 1
        $x_1_4 = "The only way to decrypt your file is to buy my decrytion tool" ascii //weight: 1
        $x_1_5 = "Your personid :" ascii //weight: 1
        $x_1_6 = "send ITSBTC btc to my wallet address ITSADDR" ascii //weight: 1
        $x_1_7 = "finally you will kown it's vain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_Win32_FileCoder_SBR_2147763442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.SBR!MSR"
        threat_id = "2147763442"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WW91ciBmaWxlcyBoYXZlIGJlZW4gZW5jcnlwdGVkIHVzaW5nIG1pbGl0YXJ5IGdyYWRlI" ascii //weight: 2
        $x_2_2 = "IFRoZXkgY2FuIG5ldmVyIGJlIGFjY2Vzc2VkIGFnYWluIHdpdGhvdXQgYnV5aW5nIGEgZGVjcnlwdGlvbiBrZXku" ascii //weight: 2
        $x_2_3 = "c21hdWdyd21heXN0dGhmeHA3MnRsbWRicnpsd2RwMnB4dHB2dHp2aGt2NXBwZzNkaWZpd29uYWQub25pb24u" ascii //weight: 2
        $x_2_4 = "src/Lock/internal/pkg/encryption" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_AB_2147766646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.AB!MTB"
        threat_id = "2147766646"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Public\\Music\\key.txt" ascii //weight: 1
        $x_1_2 = "Your files have been encrypted!" ascii //weight: 1
        $x_1_3 = "Decrypting files" ascii //weight: 1
        $x_1_4 = "If you want to decrypt your files, send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_AB_2147766646_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.AB!MTB"
        threat_id = "2147766646"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RANSOMWARE_KDF_INFO" ascii //weight: 1
        $x_1_2 = "NUVD=" ascii //weight: 1
        $x_1_3 = "expand 32-byte k" ascii //weight: 1
        $x_1_4 = "README_encrypted.txt" ascii //weight: 1
        $x_1_5 = "Unable to encrypt" ascii //weight: 1
        $x_1_6 = "src/bin/ransomware.rs" ascii //weight: 1
        $x_1_7 = "Lazy instance has previously been poisoned" ascii //weight: 1
        $x_1_8 = "ATTENTION!!! ALL YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
        $x_1_9 = "YOU HAVE TO PAY $1000 DOLLARS TO UNLOCK YOUR FILES" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Ransom_Win32_FileCoder_SV_2147767750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.SV!MTB"
        threat_id = "2147767750"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If You want decrypt files please contact us on jabber:" ascii //weight: 1
        $x_1_2 = "paymeplease@sj.ms Yours PIN is:" ascii //weight: 1
        $x_1_3 = "justfile.txt" ascii //weight: 1
        $x_1_4 = "systms.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_SV_2147767750_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.SV!MTB"
        threat_id = "2147767750"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Oops, all your documents, photos, videos and databases are encrypted by the Xy Ransomware" ascii //weight: 1
        $x_1_2 = "If you want to get them back, pay 500 $ in Bitcoin to the adress 3NoxVgyO3nGBhiwqb8fhyMUPPv" ascii //weight: 1
        $x_1_3 = "You have 72 hours to pay, then ALL your files will be gone.@" ascii //weight: 1
        $x_1_4 = "E:\\Ransomware\\a\\a\\obj\\Debug\\a.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_SG_2147771166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.SG!MTB"
        threat_id = "2147771166"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "We got your documents and files encrypted and you cannot access them." ascii //weight: 1
        $x_1_2 = "lose all of your data and files. How much time would it take to recover losses? You only may guess." ascii //weight: 1
        $x_1_3 = "we will either send those data to rivals, or publish them." ascii //weight: 1
        $x_1_4 = "All we need is to earn. Should we be unfair guys, no one would work with us." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_MAK_2147781197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.MAK!MTB"
        threat_id = "2147781197"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "All your files has been encrypted" ascii //weight: 10
        $x_10_2 = "Wallpaper" ascii //weight: 10
        $x_10_3 = "README.txt" ascii //weight: 10
        $x_10_4 = {77 00 72 00 69 00 74 00 65 00 20 00 72 00 6f 00 20 00 65 00 6d 00 61 00 69 00 6c 00 20 00 [0-16] 40 00 64 00 69 00 73 00 72 00 6f 00 6f 00 74 00 2e 00 6f 00 72 00 67 00}  //weight: 10, accuracy: Low
        $x_10_5 = {77 72 69 74 65 20 72 6f 20 65 6d 61 69 6c 20 [0-16] 40 64 69 73 72 6f 6f 74 2e 6f 72 67}  //weight: 10, accuracy: Low
        $x_2_6 = "\"OS\": \"%s\"" ascii //weight: 2
        $x_2_7 = "\"CompName\": \"%s\"" ascii //weight: 2
        $x_2_8 = "\"ext\": \"%s\"" ascii //weight: 2
        $x_2_9 = "\"processes\"" ascii //weight: 2
        $x_2_10 = "\"drives\"" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_2_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_FileCoder_MBK_2147808902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.MBK!MTB"
        threat_id = "2147808902"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files has been encrypted" ascii //weight: 1
        $x_1_2 = "README.txt" ascii //weight: 1
        $x_1_3 = "the whole downloaded info will post on public news website" ascii //weight: 1
        $x_1_4 = "We have also downloaded a lot of private data from your network" ascii //weight: 1
        $x_1_5 = "put this key:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_AG_2147809078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.AG!MTB"
        threat_id = "2147809078"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Readme if you want your files!.txt" ascii //weight: 1
        $x_1_2 = "There is no way to get back your files. Happy coding" ascii //weight: 1
        $x_1_3 = "ransom.jpg" ascii //weight: 1
        $x_1_4 = ".qqbangbang" ascii //weight: 1
        $x_1_5 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_AG_2147809078_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.AG!MTB"
        threat_id = "2147809078"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mail,.bak,.cfg,.sql,.log,.doc,.xml" wide //weight: 1
        $x_1_2 = "ProgramData\\read_for_your_files.txt" wide //weight: 1
        $x_1_3 = "YOUR FILES ARE ENCRYPTED" wide //weight: 1
        $x_1_4 = "Enc dwBlAHYAdAB1AHQAaQBsACAAZQBsACAAfAAgAEYAbwByAGUAYQBjAGgALQBPAGIAagBlAGMAdAAgAHsAdwBlAHYAdAB1AHQAaQBsACAAYwBsACAAIgAkAF8" wide //weight: 1
        $x_1_5 = "Windows Defender\\mpcmdrun.exe" wide //weight: 1
        $x_1_6 = "-removedefinitions -all" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_FileCoder_MK_2147809239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.MK!MTB"
        threat_id = "2147809239"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Covid666.bat" ascii //weight: 1
        $x_1_2 = "ALL YOUR FILES ARE ENCRYPTED" ascii //weight: 1
        $x_1_3 = "Only way to get them back is to pay 1000$ worth of BTC" ascii //weight: 1
        $x_1_4 = "You became a victim of the Covid-666 Ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_MP_2147811131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.MP!MTB"
        threat_id = "2147811131"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e9 31 05 00 00 90 32 4d 0c 90 e9 42 02 00 00 50 90 e9 a6 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_JSG_2147817189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.JSG!MSR"
        threat_id = "2147817189"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Users\\sinez\\source\\repos\\GonnaCope\\GonnaCopeCryptor\\obj\\Debug\\GonnaCopeCryptor.pdb" ascii //weight: 2
        $x_1_2 = "Copium-" wide //weight: 1
        $x_1_3 = ".cope" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_PAX_2147838554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.PAX!MTB"
        threat_id = "2147838554"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT * FROM Win32_ShadowCopy" wide //weight: 1
        $x_1_2 = "cmd.exe /c C:\\Windows\\System32\\wbem\\WMIC.exe shadowcopy" wide //weight: 1
        $x_1_3 = "C:\\CONTI_LOG.txt" wide //weight: 1
        $x_1_4 = "TestLocker.pdb" ascii //weight: 1
        $x_1_5 = "DECRYPT_NOTE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_FileCoder_PBA_2147841323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.PBA!MTB"
        threat_id = "2147841323"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 d1 af 45 66 ba 1c 0b 2d 19 22 00 00 02 2d ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 89 d1 c1 e2 ?? 8b 44 24 ?? 0f b7 c9 ba 0b 72 00 00 81 f1 9e 4e 00 00 31 58 ?? 68 03 6e ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_NB_2147844792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.NB!MTB"
        threat_id = "2147844792"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 fd d0 ff ff 83 c0 0c 5a c7 40 f8 01 00 00 00 89 50 fc 66 c7 04 50 00 00 66 c7 40 f6 02 00 8b 15 80 69 4f 00 66 89 50 f4 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_BC_2147847317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.BC!ibt"
        threat_id = "2147847317"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe Delete Shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "wmic.exe Shadowcopy Delete" ascii //weight: 1
        $x_1_3 = "iisreset.exe /stop" ascii //weight: 1
        $x_1_4 = "ZgBvAHIAZQBhAGMAaAAgACgAJABpACAAaQBuACAAJAAoAGMAbQBkAC4AZQB4AGUAIAAvAGMAIABzAGM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_GJN_2147848969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.GJN!MTB"
        threat_id = "2147848969"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c C:\\Windows\\System32\\wbem\\WMIC.exe shadowcopy" wide //weight: 1
        $x_1_2 = "SELECT * FROM Win32_ShadowCopy" wide //weight: 1
        $x_1_3 = "CONTI_LOG.txt" ascii //weight: 1
        $x_1_4 = "readme.txt" ascii //weight: 1
        $x_1_5 = "DECRYPT_NOTE" ascii //weight: 1
        $x_1_6 = "Can't write key for file %s. GetLastError = %lu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_ZB_2147851139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.ZB!MTB"
        threat_id = "2147851139"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EMIMIC_LOG.txt" wide //weight: 1
        $x_1_2 = "All of your files, documents and databases are encrypted" ascii //weight: 1
        $x_1_3 = "Delete Shadow Copies" wide //weight: 1
        $x_1_4 = "powershell.exe -ExecutionPolicy Bypass \"Get-VM | Stop-VM\"" wide //weight: 1
        $x_1_5 = "$windows.~ws" wide //weight: 1
        $x_1_6 = "$windows.~bt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_ZC_2147890014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.ZC!MTB"
        threat_id = "2147890014"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IOBitUnlockerDevice" wide //weight: 1
        $x_1_2 = ".locked" wide //weight: 1
        $x_1_3 = "\\___RestoreYourFiles___.txt" wide //weight: 1
        $x_1_4 = "All your important files have been encrypted and stolen!" ascii //weight: 1
        $x_1_5 = "If you don't contact within three days, we'll start leaking data" ascii //weight: 1
        $x_1_6 = "Failed to open handle to driver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_AZ_2147894961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.AZ!MTB"
        threat_id = "2147894961"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Collecting stage finished. Found %d files. Continue encryption" wide //weight: 1
        $x_1_2 = "@.crypt" wide //weight: 1
        $x_1_3 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"" wide //weight: 1
        $x_1_4 = "ExcludeExtensions=exe|dll|xml|log|dmp" ascii //weight: 1
        $x_1_5 = "KeyFileText=Files on this computer encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_YAA_2147899977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.YAA!MTB"
        threat_id = "2147899977"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0e 33 c8 89 4e 20 47 83 c6 04 3b 7d f8}  //weight: 1, accuracy: High
        $x_1_2 = {33 c2 41 89 4d fc 83 fb 04 75 ?? 8b c8 c1 e9 10 81 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_MVK_2147901179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.MVK!MTB"
        threat_id = "2147901179"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 04 3b 99 f7 f9 0f b6 44 15 ?? 30 47 fe 8d 04 3e 99 f7 f9 0f b6 44 15 f0 30 47 ff 8b 45 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c7 99 f7 f9 0f b6 44 15 ?? 30 47 01 8b 45 e0 03 c7 99 f7 f9 0f b6 44 15 f0 30 47 02 83 c7 05 8d 04 3b 83 f8 64 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_SGA_2147901993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.SGA!MTB"
        threat_id = "2147901993"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your important files are encrypted!" ascii //weight: 1
        $x_1_2 = "Do not rename encrypted files." ascii //weight: 1
        $x_1_3 = "Restore-My-Files.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_MV_2147906178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.MV!MTB"
        threat_id = "2147906178"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 c3 0c 87 d7 2b cf 23 d3 33 f9 0b ca 23 d7 0b cb 87 d3 33 d9}  //weight: 1, accuracy: High
        $x_1_2 = {32 c2 88 07 90 46 47 90 49 83 f9 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_FileCoder_RHL_2147912650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.RHL!MTB"
        threat_id = "2147912650"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "seckey" ascii //weight: 1
        $x_1_2 = "pubkey" ascii //weight: 1
        $x_1_3 = "GetLogicalDriveStringsW" ascii //weight: 1
        $x_1_4 = "CryptGenRandom" ascii //weight: 1
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_6 = "Process32First" ascii //weight: 1
        $x_1_7 = "Thread32Next" ascii //weight: 1
        $x_1_8 = "Module32Next" ascii //weight: 1
        $x_2_9 = {50 45 00 00 4c 01 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0a 00 00 04 02 00 00 c2 01 00 00 00 00 00 91 4a 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_RHJ_2147913363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.RHJ!MTB"
        threat_id = "2147913363"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vssadmin Delete Shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "wmic shadowcopy delete" ascii //weight: 1
        $x_1_3 = "GlitchByte.bmp" ascii //weight: 1
        $x_1_4 = "FindNextFileA" ascii //weight: 1
        $x_1_5 = ".GLBT" ascii //weight: 1
        $x_1_6 = "if you thought this ransomware uses XOR" ascii //weight: 1
        $x_1_7 = "you're wrong" ascii //weight: 1
        $x_1_8 = "system32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_2_9 = {50 45 00 00 4c 01 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 02 26 00 2a 00 00 00 ?? 25 00 00 02 00 00 de 10}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_RHM_2147913420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.RHM!MTB"
        threat_id = "2147913420"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 d0 e9 ba 01 0f b7 05 d2 e9 ba 01 25 ff 7f 00 00 c3}  //weight: 2, accuracy: High
        $x_2_2 = {51 56 c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 50 33 f6}  //weight: 2, accuracy: Low
        $x_2_3 = {50 45 00 00 4c 01 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 09 00 00 ac 00 00 00 ?? 7c 01 00 00 00 00 d7 1b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_SGC_2147913705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.SGC!MTB"
        threat_id = "2147913705"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {a3 34 96 71 00 a1 34 96 71 00 a3 58 dc 70 00 33 c0 a3 5c dc 70 00 33 c0 a3 60 dc 70 00 8d 43 08 a3 68 dc 70 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_RHO_2147914288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.RHO!MTB"
        threat_id = "2147914288"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Revenge" wide //weight: 1
        $x_1_2 = "Keys" wide //weight: 1
        $x_1_3 = "Stone" wide //weight: 1
        $x_2_4 = {50 45 00 00 4c 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 09 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4e 18}  //weight: 2, accuracy: Low
        $x_2_5 = {b8 31 a2 00 00 01 85 f8 e3 ff ff 8b 85 f8 e3 ff ff 8a 04 08 8b 15 ?? ?? ?? ?? 88 04 0a a1 ?? ?? ?? ?? 3d ab 05 00 00 75 0a c7 05 ?? ?? ?? ?? b0 19 00 00 41 3b c8 72 bd}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_GPAB_2147916283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.GPAB!MTB"
        threat_id = "2147916283"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin Delete Shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "wmic shadowcopy delete" ascii //weight: 1
        $x_4_3 = "\\GlitchByte.bm" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_RHZ_2147923133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.RHZ!MTB"
        threat_id = "2147923133"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0e 27 00 1a 02 00 00 92 42 01}  //weight: 2, accuracy: Low
        $x_3_2 = "DxxAlien_ReadMe.txt" wide //weight: 3
        $x_1_3 = "Are you sure this is right decription key" wide //weight: 1
        $x_1_4 = "Wallpaper set successfully" wide //weight: 1
        $x_1_5 = "Your PC is under my control and all your files are encrypted" ascii //weight: 1
        $x_1_6 = "Copy Ether Address" wide //weight: 1
        $x_1_7 = "Encrypting File" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_RHAB_2147923421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.RHAB!MTB"
        threat_id = "2147923421"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0e 27 00 fe 01 00 00 f0 63 00 00 00 00 00 67 13}  //weight: 2, accuracy: Low
        $x_3_2 = "If not, you can't recover your files forever" wide //weight: 3
        $x_1_3 = "Is this right key" wide //weight: 1
        $x_1_4 = "Wallpaper set successfully" wide //weight: 1
        $x_1_5 = "All your files have been encrypted by our Invisible Ransomware" ascii //weight: 1
        $x_1_6 = "Copy My BTC Address" wide //weight: 1
        $x_1_7 = "Copy My USDT TRC20" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_GPAC_2147924197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.GPAC!MTB"
        threat_id = "2147924197"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 2
        $x_2_2 = "wmic shadowcopy delete" ascii //weight: 2
        $x_1_3 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 1
        $x_1_4 = "wbadmin delete catalog -quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_RHAC_2147927821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.RHAC!MTB"
        threat_id = "2147927821"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0e 27 00 1a 02 00 00 2c 40 00 00 00 00 00 87 13}  //weight: 2, accuracy: Low
        $x_3_2 = "Are you sure this is right decription key? If not, you can loose all files" wide //weight: 3
        $x_1_3 = "Wallpaper set successfully." wide //weight: 1
        $x_1_4 = "DxxAlien_ReadMe.txt" wide //weight: 1
        $x_1_5 = "Copy BTC Address" wide //weight: 1
        $x_1_6 = "Copy Sola Address" wide //weight: 1
        $x_1_7 = "Your PC is under my control and all your files are encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_BAA_2147942344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.BAA!MTB"
        threat_id = "2147942344"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encrypted" ascii //weight: 1
        $x_1_2 = "Your files have been encrypted" ascii //weight: 1
        $x_1_3 = "To recover your data" ascii //weight: 1
        $x_1_4 = "Note dropped" ascii //weight: 1
        $x_1_5 = "svchost_log.txt" ascii //weight: 1
        $x_1_6 = "Important files encrypted. Check README files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCoder_BAB_2147946855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCoder.BAB!MTB"
        threat_id = "2147946855"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransom Note" ascii //weight: 1
        $x_1_2 = "Desktop wallpaper changed to ransom image" ascii //weight: 1
        $x_1_3 = "Your files have been encrypted. Contact attacker" ascii //weight: 1
        $x_1_4 = "Ransom note sent to printers" ascii //weight: 1
        $x_1_5 = "diskshadow_script.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

