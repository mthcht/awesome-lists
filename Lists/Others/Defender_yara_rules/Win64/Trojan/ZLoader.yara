rule Trojan_Win64_ZLoader_BA_2147766897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.BA!MTB"
        threat_id = "2147766897"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Speech\\Voices" wide //weight: 1
        $x_1_2 = "SRGRAMMAR" wide //weight: 1
        $x_1_3 = "WindowsSDK7-Samples-master\\winui\\speech\\tutorial\\x64\\Release\\CoffeeShop6.pdb" ascii //weight: 1
        $x_1_4 = "CryptAcquireContextA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_F_2147912096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.F"
        threat_id = "2147912096"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 6f 61 64 65 72 44 6c 6c 2e 64 6c 6c 00 (41|2d|5a) [0-36] 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_DA_2147924369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.DA!MTB"
        threat_id = "2147924369"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXCEPTION: Code=0x%08X" ascii //weight: 1
        $x_1_2 = "rax=0x%p, rbx=0x%p, rdx=0x%p, rcx=0x%p, rsi=0x%p, rdi=0x%p, rbp=0x%p, rsp=0x%p, rip=0x%p" ascii //weight: 1
        $x_1_3 = "[-] Request limit reached." ascii //weight: 1
        $x_1_4 = "{INJECTDATA}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_DAA_2147925487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.DAA!MTB"
        threat_id = "2147925487"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "EXCEPTION: Code=0x%" ascii //weight: 10
        $x_10_2 = "Flags=0x%" ascii //weight: 10
        $x_10_3 = "Address=0x%" ascii //weight: 10
        $x_10_4 = "expInfo=%" ascii //weight: 10
        $x_1_5 = "rip=0x%" ascii //weight: 1
        $x_1_6 = "rsp=0x%" ascii //weight: 1
        $x_1_7 = "rbp=0x%" ascii //weight: 1
        $x_1_8 = "rdi=0x%" ascii //weight: 1
        $x_1_9 = "rsi=0x%" ascii //weight: 1
        $x_1_10 = "rcx=0x%" ascii //weight: 1
        $x_1_11 = "rdx=0x%" ascii //weight: 1
        $x_1_12 = "rbx=0x%" ascii //weight: 1
        $x_1_13 = "rax=0x%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ZLoader_DB_2147925509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.DB!MTB"
        threat_id = "2147925509"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 e6 04 01 ce 89 f9 29 f1 48 63 c9 46 0f b6 1c 01 44 32 1c 38 44 88 1c 3a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_YAB_2147925527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.YAB!MTB"
        threat_id = "2147925527"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 15 48 2b c8 8a 44 0d ?? 43 32 04 02 41 88 00}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_DC_2147925602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.DC!MTB"
        threat_id = "2147925602"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 17 48 2b c8 0f b6 44 0d ?? 43 32 04 22 49 83 c2 06 43 88 44 0a}  //weight: 10, accuracy: Low
        $x_10_2 = {48 c1 ea 04 48 6b c2 11 48 2b c8 49 0f af cb 0f b6 44 0c ?? 42 32 44 0b ff 41 88 41 ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_ZLoader_DD_2147925614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.DD!MTB"
        threat_id = "2147925614"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {01 58 a6 41 2c bc 6d d7 0d 3e be 4b 43 25 db cc 79 23 4a a4 ff e2 b2 80 00 c1 6b 75 70 18 0b 5f be}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_YAC_2147925629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.YAC!MTB"
        threat_id = "2147925629"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {48 2b c8 49 0f af ca 0f b6 44 0c ?? 42 32 44 03 fa 41 88 40 fa}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_DE_2147925723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.DE!MTB"
        threat_id = "2147925723"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b c3 48 f7 e1 48 c1 ea 02 48 6b c2 16 48 2b c8 0f b6 44 0d ?? 43 32 44 22 ?? 43 88 44 0a fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_DF_2147925724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.DF!MTB"
        threat_id = "2147925724"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c9 41 81 c0 b6 2f 00 00 44 8d 49 ?? ff 15 07 00 44 8b 83}  //weight: 10, accuracy: Low
        $x_1_2 = "XVRGue" ascii //weight: 1
        $x_1_3 = "rAJUeuNfNSCR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_DG_2147925725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.DG!MTB"
        threat_id = "2147925725"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[-] Request limit reached." ascii //weight: 10
        $x_10_2 = "{INJECTDATA}" ascii //weight: 10
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "LdrDll.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_DH_2147925726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.DH!MTB"
        threat_id = "2147925726"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b4 bd 0b 11 1d 63 0b 0c 6d 01 7d e9 5b 10 d9 39 58 20 15 5d 61 56 a0 b8 62 2b 21 56 03 0f 1d 47 8c 39 74 34 fd c1 3d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_YAD_2147925755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.YAD!MTB"
        threat_id = "2147925755"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {49 8b c4 48 f7 e1 48 c1 ea 04 48 ?? ?? ?? 48 03 c0 48 2b c8 0f b6 44 0c ?? 43 32 44 0f ?? 41 88 41}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_YAE_2147925756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.YAE!MTB"
        threat_id = "2147925756"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {48 6b c2 13 48 2b c8 49 0f af cb 0f b6 44 0c ?? 42 32 44 0b fb 41 88 41 fb 41 8d 42}  //weight: 11, accuracy: Low
        $x_11_2 = {48 03 c0 48 2b c8 49 0f af cb 0f b6 44 0c ?? 42 32 44 17 ff 41 88 42}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_ZLoader_CY_2147926381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.CY!MTB"
        threat_id = "2147926381"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 2b c8 48 0f af cb 0f b6 44 0c 20 43 32 44 13 ff 41 88 42 ff 41 81 f9 c1 e0 01 00 72}  //weight: 3, accuracy: High
        $x_2_2 = {33 c9 41 b8 00 30 00 00 42 8b 54 20 50 44 8d 49 40 48 81 c2 80 c3 c9 01 ff d7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_GA_2147926853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.GA!MTB"
        threat_id = "2147926853"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 31 d2 41 f7 f2 45 8a 1c 14 44 30 1c 0f 48 ff c1 48 89 c8 48 81 f9 ff 3f 00 00 76 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_ZZV_2147931293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.ZZV!MTB"
        threat_id = "2147931293"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 ca 48 c1 ea 3f 48 c1 f9 ?? 01 d1 89 ca c1 e2 04 01 ca 89 c1 29 d1 48 63 c9 42 0f b6 0c 31 32 0c 06 88 0c 07 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

