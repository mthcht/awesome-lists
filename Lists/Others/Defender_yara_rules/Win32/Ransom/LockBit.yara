rule Ransom_Win32_LockBit_A_2147745590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.A!MTB"
        threat_id = "2147745590"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\LockBit" wide //weight: 1
        $x_1_2 = "All your important files are encrypted!" ascii //weight: 1
        $x_1_3 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_4 = "We will decrypt 1 file for test" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockBit_PA_2147748589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.PA!MTB"
        threat_id = "2147748589"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_2 = "SOFTWARE\\LockBit" wide //weight: 1
        $x_1_3 = "All your important files are encrypted!" ascii //weight: 1
        $x_1_4 = "Restore-My-Files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockBit_PA_2147748589_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.PA!MTB"
        threat_id = "2147748589"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all /quiet" wide //weight: 1
        $x_1_2 = "bcdedit /set {default} recoveryenabled no" wide //weight: 1
        $x_1_3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" wide //weight: 1
        $x_1_4 = "Restore-My-Files" ascii //weight: 1
        $x_1_5 = "All your important files are encrypted" ascii //weight: 1
        $x_1_6 = "We accept Bitcoin" ascii //weight: 1
        $x_1_7 = "Do not try to decrypt using third party software, it may cause permanent data loss" ascii //weight: 1
        $x_1_8 = "All your files are encrypted" ascii //weight: 1
        $x_1_9 = "Over time, the cost increases, do not waste your time" ascii //weight: 1
        $x_1_10 = "antidote is only among the creators of the virus" ascii //weight: 1
        $x_1_11 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_12 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 1
        $x_1_13 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_LockBit_PA_2147748589_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.PA!MTB"
        threat_id = "2147748589"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LockBit Ransom" ascii //weight: 1
        $x_1_2 = "\\LockBit-note.hta" wide //weight: 1
        $x_1_3 = "SOFTWARE\\LockBit" ascii //weight: 1
        $x_1_4 = "All your files are encrypted by LockBit" ascii //weight: 1
        $x_1_5 = "Restore-My-Files.txt" ascii //weight: 1
        $x_1_6 = "/c vssadmin delete shadows /all /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_LockBit_PB_2147752636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.PB!MTB"
        threat_id = "2147752636"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Restore-My-Files.txt" wide //weight: 1
        $x_1_2 = ".lockbit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockBit_PB_2147752636_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.PB!MTB"
        threat_id = "2147752636"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 76 00 c7 85 [0-6] 73 00 73 00 [0-6] 61 00 64 00 [0-6] 6d 00 69 00 [0-6] 6e 00 20 00 [0-6] 64 00 65 00 [0-6] 6c 00 65 00 [0-6] 74 00 65 00 [0-6] 20 00 73 00 [0-6] 68 00 61 00 [0-6] 64 00 6f 00 [0-6] 77 00 73 00 [0-6] 20 00 2f 00 [0-6] 61 00 6c 00 [0-6] 6c 00 20 00 [0-6] 2f 00 71 00 [0-6] 75 00 69 00 [0-6] 65 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {77 00 62 00 c7 85 [0-4] 61 00 64 00 [0-6] 6d 00 69 00 [0-6] 6e 00 20 00 [0-6] 64 00 65 00 [0-6] 6c 00 65 00 [0-6] 74 00 65 00 [0-6] 20 00 63 00 [0-6] 61 00 74 00 [0-6] 61 00 6c 00 [0-6] 6f 00 67 00 [0-6] 20 00 2d 00 [0-6] 71 00 75 00 [0-6] 69 00 65 00 [0-6] 74 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Restore-My-Files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockBit_SK_2147756502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.SK!MTB"
        threat_id = "2147756502"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 33 c3 c7 45 ?? ?? ?? ?? ?? 66 89 45 ?? 0f b7 05 ?? ?? ?? ?? 66 33 c3 c7 45 ?? ?? ?? ?? ?? 66 89 45 ?? 0f b7 05 ?? ?? ?? ?? 66 33 c3 c7 45 ?? ?? ?? ?? ?? 66 89 45 ?? 0f b7 05 ?? ?? ?? ?? 66 33 c3 c7 45 ?? ?? ?? ?? ?? 66 89 45 ?? 0f b7 05}  //weight: 2, accuracy: Low
        $x_2_2 = {85 c0 74 0a 8d 8c 24 ?? ?? ?? ?? 51 ff d0 8d 84 24 ?? ?? ?? ?? c7 84 24 ?? ?? ?? ?? 3c 00 00 00 89 84 24 ?? ?? ?? ?? 8d 44 24 ?? 89 84 24 ?? ?? ?? ?? 8b 44 24 ?? 89 84 24 ?? ?? ?? ?? 8d 84 24 ?? ?? ?? ?? 50 c7 84 24 ?? ?? ?? ?? 00 00 00 00 c7 84 24 ?? ?? ?? ?? 00 00 00 00 c7 84 24 ?? ?? ?? ?? 00 00 00 00 c7 84 24 ?? ?? ?? ?? 00 00 00 00 c7 84 24 ?? ?? ?? ?? 00 00 00 00 ff 15 ?? ?? ?? ?? 68 e8 03 00 00 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockBit_AA_2147818734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.AA"
        threat_id = "2147818734"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {33 c0 8b 55 0c 8b 75 08 ac 33 c9 b9 30 00 00 00 8d 0c 4d 01 00 00 00 02 f1 2a f1 33 c9 b9 06 00 00 00 8d 0c 4d 01 00 00 00 d3 ca 03 d0 90 85 c0 75 d6}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockBit_AB_2147818735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.AB"
        threat_id = "2147818735"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {8b 55 0c 8b 75 08 66 ad 90 66 83 f8 41 72 0b 66 83 f8 5a 77 05 66 83 c8 20 90 33 c9 b9 30 00 00 00 8d 0c 4d 01 00 00 00 02 f1 2a f1 33 c9 b9 06 00 00 00 8d 0c 4d 01 00 00 00 d3 ca 03 d0 90 85 c0 75 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockBit_AC_2147818736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.AC"
        threat_id = "2147818736"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {8b 4d 08 8b 55 0c ?? 81 31 ?? ?? ?? ?? f7 11 ?? 83 c1 04 4a 75 f1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockBit_AD_2147818737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.AD"
        threat_id = "2147818737"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {8b 0e 0f b6 d1 0f b6 dd 57 8d bd fc fe ff ff 8a 04 3a 8a 24 3b c1 e9 10 83 c6 04 0f b6 d1 0f b6 cd 8a 1c 3a 8a 3c 39 5f 8a d4 8a f3 c0 e0 02 c0 eb 02 c0 e6 06 c0 e4 04 c0 ea 04 0a fe 0a c2 0a e3 88 07 88 7f 02 88 67 01 ff 4d fc 8d 7f 03 75 af 58}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockBit_PD_2147829188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.PD!MTB"
        threat_id = "2147829188"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f9 2b cf 0f b6 16 03 c2 46 03 d8 4f 75 f5 bf ?? ?? ?? ?? 81 f7 ?? ?? ?? ?? 33 d2 f7 f7 52 8b c3 33 d2 f7 f7 8b da 58 85 c9 75 c5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockBit_PE_2147841512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.PE!MTB"
        threat_id = "2147841512"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Po0q7OPs7I" wide //weight: 1
        $x_1_2 = "Restore-My-Files.txt" wide //weight: 1
        $x_1_3 = "All your important files are encrypted!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockBit_ADA_2147845365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.ADA!MTB"
        threat_id = "2147845365"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {fc 9c c9 2d ?? ?? ?? ?? ac d0 41 ?? 1d ?? ?? ?? ?? 55 c9 ce 8d 76 ?? 4e e6 ?? 7b ?? be ?? ?? ?? ?? 8c 5d ?? 43 05}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockBit_PF_2147846983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.PF!MTB"
        threat_id = "2147846983"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be c0 83 e8 0d 88 44 0c ?? 41 83 f9 0c 72}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f0 6c 33 d2 88 44 24 ?? 8a 44 24 ?? 8a 44 14 ?? 8b 4c 24 ?? 02 ca 0f be c0 33 c8 88 4c 14 ?? 42 83 fa 0b 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockBit_PG_2147900108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.PG!MTB"
        threat_id = "2147900108"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LockBit.JPG" wide //weight: 1
        $x_1_2 = "Your data is stolen and encrypted." ascii //weight: 1
        $x_1_3 = "LockBit 3.0 the world's fastest and most stable ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockBit_SA_2147913037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.SA"
        threat_id = "2147913037"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "that is located in every encrypted folder." wide //weight: 1
        $x_1_2 = "Would you like to earn millions of dollars?" wide //weight: 1
        $x_2_3 = "3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1D709C3C4AE9B7" wide //weight: 2
        $x_2_4 = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion" wide //weight: 2
        $x_1_5 = "Active:[ %d [                  Completed:[ %d" wide //weight: 1
        $x_2_6 = "\\LockBit_Ransomware.hta" ascii //weight: 2
        $x_1_7 = "Ransomware.hta" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_LockBit_K_2147929342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.K"
        threat_id = "2147929342"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Version: LockBitGreen" ascii //weight: 1
        $x_1_2 = {7e 7e 7e 20 59 6f 75 20 68 61 76 65 20 62 65 65 6e 20 61 74 74 61 63 ?? 65 64 20 62 79 20 4c 6f 63 6b 42 69 74 20 34}  //weight: 1, accuracy: Low
        $n_1_3 = "[%d] Decrypted:" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Ransom_Win32_LockBit_AL_2147934827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockBit.AL!MTB"
        threat_id = "2147934827"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {80 30 fa 80 70 0a fa 83 c0 14 39 f0 75}  //weight: 4, accuracy: High
        $x_1_2 = {c7 04 24 10 27 00 00 ff d3 83 ec 04 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

