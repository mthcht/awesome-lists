rule Trojan_Win32_Fragtor_FL_2147799117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.FL!MTB"
        threat_id = "2147799117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b d0 66 81 e2 ff 03 0f b7 d2 89 15 48 97 48 00 0f b7 c0 c1 e8 0a a3 4c 97 48 00 be e0 d2 40 00 bf 0c 61 48 00 b9 08 00 00 00 f3 a5 83 3d c4 60 48 00 02 0f 85 a7 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {32 33 00 00 00 00 6f 39 32 32 00 00 00 00 55 8b ec 83 c4 f8 89 55 f8 89 45 fc 33 c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_HBAI_2147808773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.HBAI!MTB"
        threat_id = "2147808773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c3 33 d4 0f b6 15 ?? ?? ?? ?? f5 3b e5 33 c2 81 e6 ff}  //weight: 10, accuracy: Low
        $x_10_2 = {b2 08 66 d3 f2 13 d7 a1 ?? ?? ?? ?? 80 d6 ?? 0f ac ea ?? 83 c4 f8 0f b7 d4}  //weight: 10, accuracy: Low
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_SIB_2147813608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.SIB!MTB"
        threat_id = "2147813608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<program name unknown>" wide //weight: 1
        $x_1_2 = {6a 40 68 00 ?? ?? ?? 8b 55 ?? 52 6a 00 ff 15 ?? ?? ?? ?? 89 45 ?? 6a 00 8d 45 ?? 50 8b 4d 01 51 8b 55 03 52 8b 45 ?? 50 ff 15 ?? ?? ?? ?? c7 45 ?? 00 00 00 00 8b 55 09 3b 55 01 6a 00 6a 00 8b 45 03 50 ff 15 ?? ?? ?? ?? c2}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 08 80 c1 ?? 8b 55 ?? 03 55 ?? 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_SIBA_2147813609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.SIBA!MTB"
        threat_id = "2147813609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<program name unknown>" wide //weight: 1
        $x_1_2 = {6a 40 68 00 ?? ?? ?? 8b 55 ?? 52 6a 00 ff 15 ?? ?? ?? ?? 89 45 ?? 6a 00 8d 45 ?? 50 8b 4d 01 51 8b 55 03 52 8b 45 ?? 50 ff 15 ?? ?? ?? ?? c7 45 ?? 00 00 00 00 8b 55 09 3b 55 01 6a 00 6a 00 8b 45 03 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {88 0a 8b 45 ?? 03 45 ?? 0f b6 08 81 c1 ?? ?? ?? ?? 8b 55 00 03 55 01 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_EL_2147828893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.EL!MTB"
        threat_id = "2147828893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stealedDB" ascii //weight: 1
        $x_1_2 = "-r make regiser values using stealed database." ascii //weight: 1
        $x_1_3 = "-d read and decrypt every line from database." ascii //weight: 1
        $x_1_4 = "Way to go\\TOV\\4Lab" ascii //weight: 1
        $x_1_5 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Warper.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_RD_2147839497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.RD!MTB"
        threat_id = "2147839497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 95 20 4f 09 8b ce f7 ee d1 fa 8b c2 c1 e8 1f 03 c2 6b c0 37 2b c8 83 c1 35 66 31 8c 75 10 c2 ff ff 46 81 fe b6 1e 00 00 7c d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_RC_2147844006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.RC!MTB"
        threat_id = "2147844006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 34 24 8a 6d 00 8a 0e 31 f6 30 cd 88 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_RC_2147844006_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.RC!MTB"
        threat_id = "2147844006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://imgcache.cloudservicesdevc.tk/picturess" ascii //weight: 1
        $x_1_2 = "aHR0cDovL2ltZ2NhY2hlLmNsb3Vkc2VydmljZXNkZXZjLnRrL3BpY3R1cmVzcy8yMDIzLw==" ascii //weight: 1
        $x_1_3 = "RLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_GJT_2147850272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.GJT!MTB"
        threat_id = "2147850272"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 ce c1 e9 08 33 d1 66 8b 54 93 04 c1 e6 08 66 33 d6 8b f2 eb ?? 8b 55 f0 0f b6 12 8b 4d ec 81 e1 ?? ?? ?? ?? 33 d1 8b 54 93 04 8b 4d ec c1 e9 08 33 d1 89 55 ec ff 45 f0 48}  //weight: 10, accuracy: Low
        $x_1_2 = "crvsx.zapto.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_KAA_2147851488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.KAA!MTB"
        threat_id = "2147851488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {21 d2 8b 06 ba ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 81 e0 ?? ?? ?? ?? 4a f7 d7 31 03 81 c7 e8 2c e5 ef 29 f9 4a 43 09 d2 49 46 89 fa 21 d1 4f 81 fb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_KAB_2147852099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.KAB!MTB"
        threat_id = "2147852099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 cb 8b 3e 81 c0 ?? ?? ?? ?? 09 db 81 e7 ?? ?? ?? ?? 21 cb 81 e8 ?? ?? ?? ?? 31 3a 01 db 89 d8 42 01 cb 09 c3 81 c6 ?? ?? ?? ?? 48 09 db 81 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_KAB_2147852099_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.KAB!MTB"
        threat_id = "2147852099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {83 f1 55 8d 52 01 66 89 0e 8d b5 ?? ?? ff ff 0f b7 04 56 8d 34 56 8b c8 66 85 c0 75}  //weight: 20, accuracy: Low
        $x_8_2 = "C:\\Users\\HP\\source\\repos\\Project RO\\Release\\Project RO.pdb" ascii //weight: 8
        $x_7_3 = ".ragnarok" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_SPK_2147852351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.SPK!MTB"
        threat_id = "2147852351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 40 68 00 10 00 00 68 74 12 00 00 6a 00 55 ff 15 ?? ?? ?? ?? 85 c0 0f 84}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_KAE_2147890144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.KAE!MTB"
        threat_id = "2147890144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 0b 81 c0 ?? ?? ?? ?? 29 d7 81 e1 ?? ?? ?? ?? 81 ef ?? ?? ?? ?? f7 d2 31 0e f7 d2 29 fa 46 47 4f 43 29 c2 89 c7 81 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_KAE_2147890144_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.KAE!MTB"
        threat_id = "2147890144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Welcome to Bartender Simulator!" ascii //weight: 1
        $x_1_2 = "gcry_sexp_build_array" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_B_2147890441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.B!MTB"
        threat_id = "2147890441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 29 44 24 60 0f 29 44 24 70 8b 91 ?? ?? ?? ?? 33 54 08 04 89 54 0c 64 83 c1 04 83 f9 20 72 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_B_2147890441_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.B!MTB"
        threat_id = "2147890441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 f8 8b c7 33 c9 ba 10 00 00 00 e8 ?? ?? ?? ?? 89 5f 0c 33 c0 89 47 04 c6 47 08 7f c6 47 09 01 33 c0 89 07 bb 30 00 00 00 8d ?? ?? 50 57 6a 00 e8 ?? ?? ?? ?? 8b f0 81 07 40 77 1b 00 4b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_ARA_2147893463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.ARA!MTB"
        threat_id = "2147893463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 14 08 80 ea 7a 80 f2 19 88 14 08 40 3b c6 7c ef}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_ARA_2147893463_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.ARA!MTB"
        threat_id = "2147893463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 1a 99 59 f7 f9 83 c2 41 66 89 54 7d d4 47 83 ff 0a 7c e7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_RG_2147893746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.RG!MTB"
        threat_id = "2147893746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 a6 4f 87 af 7a ea dc 60 43 40 1f 33 3c 3b 3a 0c b8 f5 9b ea ec 45 0c eb 59 3a f2 34 58 8b fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_KAF_2147895887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.KAF!MTB"
        threat_id = "2147895887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 0a 4e 81 c6 ?? ?? ?? ?? 40 81 e1 ?? ?? ?? ?? 09 f6 4b 81 c6 ?? ?? ?? ?? 31 0f f7 d0 b8 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 01 c3 01 f6 81 c2 ?? ?? ?? ?? 89 c3 4e 21 f0 81 ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_KA_2147896230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.KA!MTB"
        threat_id = "2147896230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 31 29 d3 01 df 81 e6 ?? ?? ?? ?? f7 d3 01 da 31 30 01 da 81 eb ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 40 43 21 d3 81 c1 ?? ?? ?? ?? 01 df 09 d7 81 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_GPC_2147896250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.GPC!MTB"
        threat_id = "2147896250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {b8 67 66 66 66 f7 ea c1 fa 02 8b c2 c1 e8 1f 03 c2 8b 55 fc 8a c8 c0 e0 02 02 c8 8a c2 02 c9 2a c1 04 30 30 44 15 f0 42 89 55 fc}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NFA_2147897196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NFA!MTB"
        threat_id = "2147897196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 ff 3b cf 76 2e 6a e0 58 33 d2 f7 f1 3b 45 ?? 1b c0 40 75 1f e8 1c 9e ff ff c7 00 0c}  //weight: 5, accuracy: Low
        $x_1_2 = "MJPGC.TMP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NFA_2147897196_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NFA!MTB"
        threat_id = "2147897196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kontaktplus.de" ascii //weight: 1
        $x_1_2 = "hacker-spider.de" ascii //weight: 1
        $x_1_3 = "smsfake.de" ascii //weight: 1
        $x_1_4 = "erotikstudio69.com" ascii //weight: 1
        $x_1_5 = "kontaktanzeigendb.de" ascii //weight: 1
        $x_1_6 = "ES*sendman" ascii //weight: 1
        $x_1_7 = "sms-cat.de" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_MKV_2147897904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.MKV!MTB"
        threat_id = "2147897904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 1c 03 32 18 83 c0 04 88 5c 28 fc 8b 5c 24 14 0f b6 1c 0b 32 58 fd 83 c1 04 88 59 fc 0f b6 58 fe 32 5f ff 83 c7 04 88 59 fd 0f b6 58 ff 32 5f fc ff 4c 24 18 88 59 fe 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AFG_2147898089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AFG!MTB"
        threat_id = "2147898089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 06 03 05 88 65 41 00 6a 00 6a 04 68 88 65 41 00 50 57 ff d3 83 c6 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AFG_2147898089_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AFG!MTB"
        threat_id = "2147898089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ca c1 f9 06 83 e2 3f 6b d2 38 8b 0c 8d 48 8f 50 00 88 44 11 29 8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 48 8f 50 00 8b 45 14 c1 e8 10 32 44 11 2d 24 01 30 44 11 2d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AFG_2147898089_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AFG!MTB"
        threat_id = "2147898089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 05 70 48 01 10 a2 10 53 01 10 0f b6 05 71 48 01 10 a2 11 53 01 10 0f b6 05 72 48 01 10 a2 12 53 01 10 0f b6 05 73 48 01 10 a2 13 53 01 10 0f b6 05 74 48 01 10 a2 14 53 01 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AFG_2147898089_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AFG!MTB"
        threat_id = "2147898089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c8 6a 40 9c 1c 8d c1 c3 fe c1 86 08 0e 53 50 c7 86 b0 6c 0e a6 1a 05 cb a5 dd b4 12 0a b8 c0 4b e5 6b 4f 30 88 16 22 66 18 c4 31 d8 d3 b9 7c df a0 17 a4 0b a8 ac ad d9 cc 96}  //weight: 3, accuracy: High
        $x_2_2 = {2a 2c 7f 3a 51 a0 0c b6 81 28 09 be 9f cb b7 81 2c 0b 30 34 88 81 38 17 40 cb e5 72 f9 0b 44 48 4c 50 38 80 00 9f 54 8b c1 bc a0 f1 7e c1 df b1 da c2 6a 08 59 8b fe f3 ab}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_KAG_2147898863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.KAG!MTB"
        threat_id = "2147898863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {99 f7 ff 0f b6 81 ?? ?? ?? ?? c0 c8 03 32 82 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 8d 42 01 99}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NF_2147899073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NF!MTB"
        threat_id = "2147899073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 0d 53 e8 ?? ?? ?? ?? 59 85 c0 75 a9 eb 07 e8 ?? ?? ?? ?? 89 30 e8 d4 0e 00 00 89 30 8b c7 5f}  //weight: 5, accuracy: Low
        $x_1_2 = "WkV21TSav" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NF_2147899073_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NF!MTB"
        threat_id = "2147899073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {a1 c8 4f 46 00 6b c9 ?? 03 c8 eb 11 8b 55 ?? 2b 50 0c 81 fa 00 00 10 00 72 09 83 c0 ?? 3b c1 72 eb 33 c0}  //weight: 5, accuracy: Low
        $x_1_2 = "GZGLXT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NF_2147899073_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NF!MTB"
        threat_id = "2147899073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "libyugv86.dll" ascii //weight: 5
        $x_5_2 = "Software\\publub\\DuvApp" ascii //weight: 5
        $x_2_3 = "gcry_md_setkey" ascii //weight: 2
        $x_2_4 = "TrialExpire" ascii //weight: 2
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NF_2147899073_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NF!MTB"
        threat_id = "2147899073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Leveraging DKOM to achieve LPE" ascii //weight: 2
        $x_2_2 = "Calling Write64 wrapper to overwrite current EPROCESS->Token" ascii //weight: 2
        $x_1_3 = "Device\\Mup\\;Csc\\.\\." wide //weight: 1
        $x_1_4 = "Current EPROCESS address" ascii //weight: 1
        $x_1_5 = "Current THREAD address" ascii //weight: 1
        $x_1_6 = "System EPROCESS address" ascii //weight: 1
        $x_1_7 = "cmd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NF_2147899073_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NF!MTB"
        threat_id = "2147899073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DETCEJENIW trojan setup" wide //weight: 2
        $x_2_2 = "The software you just executed is considered malware" wide //weight: 2
        $x_1_3 = "This malware will harm your computer and makes it unusable" wide //weight: 1
        $x_1_4 = "If you know what this malware does and are using a safe environment to test, press Yes to start it" wide //weight: 1
        $x_1_5 = "THE CREATOR IS NOT RESPONSIBLE FOR ANY DAMAGE MADE USING THIS MALWARE!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AMBI_2147900303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AMBI!MTB"
        threat_id = "2147900303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 da 09 fe 31 f2 88 14 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NFR_2147900602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NFR!MTB"
        threat_id = "2147900602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GMUi.Run" wide //weight: 2
        $x_2_2 = "iUqm.rep" wide //weight: 2
        $x_2_3 = "OWjuxD" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NFR_2147900602_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NFR!MTB"
        threat_id = "2147900602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "conpen.bat" ascii //weight: 1
        $x_1_2 = "hao.wz1949.com" ascii //weight: 1
        $x_1_3 = "pipi_dae_473.exe" ascii //weight: 1
        $x_1_4 = "hhmmsszzz.ini" ascii //weight: 1
        $x_1_5 = "fjiej.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_ASFA_2147902863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.ASFA!MTB"
        threat_id = "2147902863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c7 00 53 6f 66 74 c7 40 04 77 61 72 65 c7 40 08 5c 4d 69 63 c7 40 0c 72 6f 73 6f c7 40 10 66 74 5c 57 c7 40 14 69 6e 64 6f c7 40 18 77 73 5c 43}  //weight: 5, accuracy: High
        $x_5_2 = {41 75 74 6f 52 75 6e 00 43 50 55 5f 49 64 65 6e 74 69 66 69 63 61 74 69 6f 6e 00 44 4c 4c 5f 49 6e 6a 65 63 74 69 6f 6e 00 44 65 62 75 67 67 65 72 5f 49 64 65 6e 74 69 66 69 63 61 74 69 6f 6e 00 44 65 63 6f 64 65 5f 42 61 73 65 36 34 00 44 65 6c 65 74 65 5f 46 69 6c 65 00 44 65 6c 65 74 65 5f 49 74 73 65 6c 66 00 4c 6f 61 64 5f 46 72 6f 6d 5f 46 69 6c 65 00 52 75 6e 5f 46 72 6f 6d 5f 4d 65 6d 6f 72 79 00 53 74 72 69 6e 67 5f 58 4f 52}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fragtor_AMMC_2147904957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AMMC!MTB"
        threat_id = "2147904957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 f4 8b 45 ec 8d 34 02 8b 55 f4 8b 45 08 01 d0 0f b6 00 88 45 e7 8b 5d f4 8b 45 0c 89 04 24 e8 ?? ?? ?? ?? 89 c1 89 d8 ba ?? ?? ?? ?? f7 f1 8b 45 0c 01 d0 0f b6 00 32 45 e7 88 06 83 45 f4 01 8b 45 f4 3b 45 f0 7c}  //weight: 2, accuracy: Low
        $x_2_2 = {5f 44 65 62 75 67 67 65 72 5f 49 64 65 6e 74 69 66 69 63 61 74 69 6f 6e 00 5f 43 50 55 5f 49 64 65 6e 74 69 66 69 63 61 74 69 6f 6e 00 5f 53 74 72 69 6e 67 5f 58 4f 52 00 5f 44 4c 4c 5f 49 6e 6a 65 63 74 69 6f 6e 00 5f 4c 6f 61 64 5f 46 72 6f 6d 5f 46 69 6c 65 00 5f 44 65 63 6f 64 65 5f 42 61 73 65 36 34 00 5f 52 75 6e 5f 46 72 6f 6d 5f 4d 65 6d 6f 72 79 00 5f 44 65 6c 65 74 65 5f 46 69 6c 65}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fragtor_GZZ_2147905285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.GZZ!MTB"
        threat_id = "2147905285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 41 d3 d6 44 8b f4 44 31 14 24 49 c1 f6 4d 45 02 f0 41 5e 40 80 ff 94 f5 41 84 c4 4d 63 d2 49 3b f6 f5 4d 03 ea e9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 f2 5d 51 69 70}  //weight: 10, accuracy: Low
        $x_1_2 = ".imports" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_HNS_2147905555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.HNS!MTB"
        threat_id = "2147905555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 00 02 00 00 73 0e 0f be 4c 38 08 33 c8 88 4c 38 08 40 eb e8}  //weight: 1, accuracy: High
        $x_1_2 = {52 00 7a 00 43 00 65 00 66 00 00 00 43 00 65 00 66 00 52 00 65 00 6e 00 64 00 65 00 72 00 00 00 41 00 63 00 72 00 6f 00 00 00 00 00 52 00 7a}  //weight: 1, accuracy: High
        $x_1_3 = {00 53 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 73 00 61 00 66 00 65 00 67 00 75 00 61 00 72 00 64 00 2e 00 65 00 78 00 65 00 00 00 78 00 33 00 32 00 00 00 53 00 6d 00 61 00 64 00 61 00 76 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "%s%s\\RECYCLERS" wide //weight: 1
        $x_1_5 = "%c\\%c\\RECYCLER.BIN\\files\\%s" wide //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AMME_2147905808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AMME!MTB"
        threat_id = "2147905808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bisjee_suwfs" ascii //weight: 1
        $x_1_2 = "aseguifaehgigh" ascii //weight: 1
        $x_1_3 = "viaegjaewg_aeifgaje" ascii //weight: 1
        $x_1_4 = "xcvuybir_suifw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_HIN_2147905834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.HIN!MTB"
        threat_id = "2147905834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ca 8b c3 0f a4 c1 0d c1 e0 0d 33 d1 8b 4c 24 10 33 d8 8b c3 0f ac d0 ?? 32 c3 30 04 0f 41 89 4c 24 ?? 83 f9 0e 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NA_2147905914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NA!MTB"
        threat_id = "2147905914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "aidwf_ivforu" ascii //weight: 5
        $x_5_2 = "buyyd_asfodv" ascii //weight: 5
        $x_5_3 = "cvydue_aufdfu" ascii //weight: 5
        $x_5_4 = "ibudod_sodogv" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NB_2147905915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NB!MTB"
        threat_id = "2147905915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Both your mom are faGG0ts :)" ascii //weight: 5
        $x_5_2 = "guocp_wffgj_tuo" ascii //weight: 5
        $x_5_3 = "libquxpvi32.dll" ascii //weight: 5
        $x_5_4 = "gcry_pk_encrypt" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NC_2147905987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NC!MTB"
        threat_id = "2147905987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "tisfu_quwof_sfiw" ascii //weight: 5
        $x_5_2 = "play_sanwsu" ascii //weight: 5
        $x_5_3 = "muasi_afjgh" ascii //weight: 5
        $x_5_4 = "gcry_pk_decrypt" ascii //weight: 5
        $x_5_5 = "gcry_pk_encrypt" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AMMF_2147906060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AMMF!MTB"
        threat_id = "2147906060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aowfawjfs_jvgjgfjgw" ascii //weight: 1
        $x_1_2 = "fkawofgjwgjs" ascii //weight: 1
        $x_1_3 = "sdhdueDviuee" ascii //weight: 1
        $x_1_4 = "xcvjhieasgega" ascii //weight: 1
        $x_1_5 = "sdgioeasgjh_ajwsdfjsad_dws" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_FA_2147906231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.FA!MTB"
        threat_id = "2147906231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 84 05 ?? ?? ?? ?? 03 c8 0f b6 c1 8b 4d 08 8a 84 05 ?? ?? ?? ?? 30 04 0a 42 89 55 0c 3b 55}  //weight: 4, accuracy: Low
        $x_1_2 = "bsiouegjhesuhg_saegiueash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_ND_2147906432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.ND!MTB"
        threat_id = "2147906432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4d d8 81 e1 01 00 00 80 79 05 49 83 c9 fe 41 85 c9 74 0b 8b 55 d8 83 c2 01 89 55 d8 eb e1}  //weight: 10, accuracy: High
        $x_5_2 = "gcry" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_M_2147906532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.M!MTB"
        threat_id = "2147906532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REG ADD hkcu\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system /v DisableTaskMgr /t reg_dword" ascii //weight: 1
        $x_1_2 = "del C:\\WINDOWS\\system32\\hal.dll" ascii //weight: 1
        $x_1_3 = "PhysicalDrive0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_MBZW_2147907266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.MBZW!MTB"
        threat_id = "2147907266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c0 29 05 ?? ?? ?? ?? 30 5c 24 ?? 8d 04 2a 89 44 24 ?? 8b c7 2b c2 0f af 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {83 3d dc 23 42 00 00 8a 91 f8 53 41 00 75 08 a1 f4 27 42 00 88 14 01 41 3b cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NE_2147907459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NE!MTB"
        threat_id = "2147907459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 f8 81 e2 01 00 00 80 79 05 4a 83 ca fe 42 85 d2 74 0b 8b 45 f8 83 c0 01 89 45 f8 eb e1}  //weight: 10, accuracy: High
        $x_5_2 = "gcry" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_KUAA_2147907910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.KUAA!MTB"
        threat_id = "2147907910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FsugsheughAxufhsruhgC" ascii //weight: 1
        $x_1_2 = "GhsrgusreghAydbsdfugsrj" ascii //weight: 1
        $x_1_3 = "isehfusehgsgh_sghushg" ascii //weight: 1
        $x_1_4 = "vbusughs_surghsurh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_KXAA_2147907982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.KXAA!MTB"
        threat_id = "2147907982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dsiughrdsugh_srugsrhug" ascii //weight: 1
        $x_1_2 = "iubduihgiursg_suighsugs" ascii //weight: 1
        $x_1_3 = "sighseughe_shugsghuseg" ascii //weight: 1
        $x_1_4 = "vbhjdurhg_esuhgshe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_RP_2147909704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.RP!MTB"
        threat_id = "2147909704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 85 9c bd ff ff 30 84 0d 9d bd ff ff 41 83 f9 17 72 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_SPGG_2147909767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.SPGG!MTB"
        threat_id = "2147909767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 45 f8 8b 45 f8 33 45 f4 31 45 fc 8b 45 fc 29 45 e8 8b 4d d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_ENG_2147910323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.ENG!MTB"
        threat_id = "2147910323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 e8 00 00 00 00 5d 81 ed 06 00 00 00 81 ed d0 1a 38 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_RU_2147910797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.RU!MTB"
        threat_id = "2147910797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fdczccxzczxcxxcxcxzcxc" ascii //weight: 1
        $x_1_2 = "DSIDSidisiidsidisdi" ascii //weight: 1
        $x_1_3 = "34zfdsdsaadsadsa" ascii //weight: 1
        $x_1_4 = "cxcxZzZzx" ascii //weight: 1
        $x_1_5 = "cvvgrerere" ascii //weight: 1
        $x_1_6 = "cxzcxzce2222" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_ASGI_2147910798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.ASGI!MTB"
        threat_id = "2147910798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 6a 40 68 ?? ?? 00 00 57 ff 15 [0-9] 8d b5 ?? ?? ff ff 8b cf 2b f7 ba}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_GXY_2147911298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.GXY!MTB"
        threat_id = "2147911298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FuiasfuisaAiaughaiuehg" ascii //weight: 1
        $x_1_2 = "TasiufgasiugAiahgfiauheg" ascii //weight: 1
        $x_1_3 = "Kiss to h3r p33zy a$$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_KAH_2147911310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.KAH!MTB"
        threat_id = "2147911310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CoisugifsruigAisgiuhsrg" ascii //weight: 1
        $x_1_2 = "Iafugijaeiguaehugsfdfds" ascii //weight: 1
        $x_1_3 = "VisiugfseuihAsrgseiugs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_SPXB_2147911492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.SPXB!MTB"
        threat_id = "2147911492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CaiugaiuegAuiasguiehg" ascii //weight: 2
        $x_2_2 = "Dasgiuoaeuhghgahieghg" ascii //weight: 2
        $x_2_3 = "Rafgafahufghauhghgh" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_ENI_2147911498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.ENI!MTB"
        threat_id = "2147911498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 e8 00 00 00 00 5d 81 ed 10 00 00 00 81 ed 0c db b5 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_OCAA_2147911930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.OCAA!MTB"
        threat_id = "2147911930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OiusogsiuhAihsgiueh" ascii //weight: 1
        $x_1_2 = "Vsagfeu9ishAsguihe" ascii //weight: 1
        $x_1_3 = "YoisgsiurhAiusrhguihse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_SPZB_2147912059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.SPZB!MTB"
        threat_id = "2147912059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FasiugfAiusagiuheg" ascii //weight: 1
        $x_1_2 = "HisushgrhAuisaheegu" ascii //weight: 1
        $x_1_3 = "Rsgoisaguisahg" ascii //weight: 1
        $x_1_4 = "Voiasafoaeg8hsauv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_OYAA_2147912538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.OYAA!MTB"
        threat_id = "2147912538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Gsaoigfasiogjk" ascii //weight: 1
        $x_1_2 = "Gsoigjseoigsejigji" ascii //weight: 1
        $x_1_3 = "Nsgfoisjgfosiegoisj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_ASGH_2147912577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.ASGH!MTB"
        threat_id = "2147912577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "NoisgisjhghAsrguier" ascii //weight: 2
        $x_2_2 = "Ojasguiseiguhshg" ascii //weight: 2
        $x_2_3 = "OsghusghuuhAiusghseurg" ascii //weight: 2
        $x_2_4 = "Kisajgfoisjgjsaf" ascii //weight: 2
        $x_2_5 = "ToiagsfoisadoiAoisgji" ascii //weight: 2
        $x_2_6 = "Vsgioesajgisauehg" ascii //weight: 2
        $x_2_7 = "JisahgfiuseahAsghuihse" ascii //weight: 2
        $x_2_8 = "MoasgfiueahAsriguhrsuh" ascii //weight: 2
        $x_2_9 = "Roasuehgfaui3D" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Fragtor_NG_2147913019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NG!MTB"
        threat_id = "2147913019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 89 45 bb 88 45 bd 66 89 45 be 88 45 c0 66 89 45 c1 88 45 c3 66 89 45 c4 88 45 c6 66 89 45 c7 88 45 c9 66 89 45 ca 88 45 cc 89 45 b4 89 45 fc}  //weight: 10, accuracy: High
        $x_1_2 = "_pcre_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NG_2147913019_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NG!MTB"
        threat_id = "2147913019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {89 4d fc 8b 45 fc 8b 4d 08 89 08 8b 55 fc 83 3a 00 75 0c 6a 0c e8 62 9a 04 00 83 c4 04 eb 1f 8b 45 fc 83 38 04 7d 17 8b 4d fc 8b 11 6b d2 18}  //weight: 3, accuracy: High
        $x_1_2 = "bitjoker2024.000webhostapp.com" wide //weight: 1
        $x_1_3 = "RemoteInject" wide //weight: 1
        $x_1_4 = "TrojanEvent" wide //weight: 1
        $x_1_5 = "TongxinProc" wide //weight: 1
        $x_1_6 = "KillCmdExe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NH_2147913020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NH!MTB"
        threat_id = "2147913020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 89 45 c7 88 45 c9 66 89 45 ca 88 45 cc 66 89 45 cd 88 45 cf 66 89 45 d0 88 45 d2 66 89 45 d3 88 45}  //weight: 10, accuracy: High
        $x_1_2 = "_pcre_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AH_2147915365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AH!MTB"
        threat_id = "2147915365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b e5 5d 8a 08 30 0a 90 90 55 8b ec 83 c4 02 83 ec 02 83 c4 08 83 ec 08 83 c4 04 83 c4 fc 83 c4 03 83 ec 03 8b e5 90 5d 8a 08 00 0a}  //weight: 3, accuracy: High
        $x_3_2 = {55 8b ec 83 c4 06 83 c4 fa 83 c4 04 83 ec 04 56 5e 83 c4 04 83 c4 fc 8b e5 90 90 5d 42 90 55 90 90 8b ec 83 c4 03 83 c4 fd 41 49 83 c4 05 83 ec 05 83 c4 01 83 ec 01 8b e5 90 90 5d 40 4f 0f 85}  //weight: 3, accuracy: High
        $x_1_3 = {50 88 55 c3 c6 45 b4 72 c6 45 b5 75 c6 45 b6 6e c6 45 b7 64 c6 45 b8 6c c6 45 b9 6c c6 45 ba 33 c6 45 bb 32 c6 45 bc 2e 88 5d bd c6 45 be 78}  //weight: 1, accuracy: High
        $x_1_4 = "formplat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AMAR_2147916536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AMAR!MTB"
        threat_id = "2147916536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 14 b0 8b 44 24 ?? 81 c2 ?? ?? ?? ?? 8b 4c b0 ?? 8b 44 24 ?? 8a 04 01 8d 4c 24 ?? 30 02 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NI_2147916585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NI!MTB"
        threat_id = "2147916585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 c8 02 33 d0 8b 45 ?? 8b c8 23 45 ?? 0b 4d ?? 23 4d ?? 0b c8 8b 45 ?? 03 c6 03 ca 03 ce 89 45 ?? 8b f0 89 4d ?? c1 c0 07}  //weight: 2, accuracy: Low
        $x_2_2 = {8b fa 8b ca c1 c7 0f c1 c1 0d 33 f9 c1 ea 0a 33 fa 8b ce 8b d6 c1 c9 07 c1 c2 0e 33 d1 c1 ee 03 33 d6 03 fa}  //weight: 2, accuracy: High
        $x_2_3 = "Global\\ArthurMutex" ascii //weight: 2
        $x_1_4 = "/c SCHTASKS.exe /Delete /TN \"Windows Update BETA\" /F" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_6 = "\\CheckMe.txt" ascii //weight: 1
        $x_1_7 = "Decryption Completed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NK_2147916586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NK!MTB"
        threat_id = "2147916586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 c8 02 33 d0 8b 45 ?? 8b c8 23 45 ?? 0b 4d ?? 23 4d ?? 0b c8 8b 45 ?? 03 c6 03 ca 03 ce 89 45 ?? 8b f0 89 4d ?? c1 c0 07}  //weight: 2, accuracy: Low
        $x_2_2 = {8b fa 8b ca c1 c7 0f c1 c1 0d 33 f9 c1 ea 0a 33 fa 8b ce 8b d6 c1 c9 07 c1 c2 0e 33 d1 c1 ee 03 33 d6 03 fa}  //weight: 2, accuracy: High
        $x_2_3 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 [0-32] 4d 00 75 00 74 00 65 00 78 00}  //weight: 2, accuracy: Low
        $x_2_4 = {47 6c 6f 62 61 6c 5c [0-32] 4d 75 74 65 78}  //weight: 2, accuracy: Low
        $x_1_5 = "/c SCHTASKS.exe /Delete /TN \"Windows Update BETA\" /F" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_7 = "Decryption Completed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fragtor_AMAU_2147916901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AMAU!MTB"
        threat_id = "2147916901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 14 b8 8b 44 ?? 24 03 54 24 ?? 8b 4c b8 ?? 8b 44 24 ?? 8a 04 01 8d 4c 24 ?? 30 02 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_MBXP_2147918466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.MBXP!MTB"
        threat_id = "2147918466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 6a ff 68 ?? f6 4b 00 68 ?? 94 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? f2 4b 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_MBXQ_2147918682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.MBXQ!MTB"
        threat_id = "2147918682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 06 4c 00 68 ?? a3 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? 02 4c 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_DA_2147919033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.DA!MTB"
        threat_id = "2147919033"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 72 0c 89 c2 c1 e2 05 8d 94 0a ?? ?? ?? ?? 89 74 93 0c ba 01 00 00 00 89 d6 d3 e6 89 c1 09 b4 83 ?? ?? ?? ?? d3 e2 09 93}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 4d 08 89 c3 8b 45 08 52 ba 01 00 00 00 d3 e2 25 ff 01 00 00 c1 f8 05 09 54 83 08 8b 5d fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_DB_2147921438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.DB!MTB"
        threat_id = "2147921438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 05 ?? ?? ?? ?? 0f b6 00 8b 55 f4 81 c2 ?? ?? ?? ?? 88 02 83 45 f4 01 8b 55 b0 8b 45 ac 01 d0 01 45 f0 8b 45 f0 3d ff 57 0a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_BG_2147921653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.BG!MTB"
        threat_id = "2147921653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 37 68 53 37 5a 31 0f b7 d2 59 81 c6 59 66 79 46 ba 54 68 c0 53 81 f6 1e e2 b5 40 80 cb f9 81 c6 ff 9a 8a 79 51 66 b9 31 28}  //weight: 3, accuracy: High
        $x_1_2 = "uEz%EmnK" ascii //weight: 1
        $x_1_3 = "AYZSsn@Y_mK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_RFAK_2147926045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.RFAK!MTB"
        threat_id = "2147926045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 e8 00 00 00 00 5d 81 ed 10 00 00 00 81 ed 14 02 9c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_MX_2147926226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.MX!MTB"
        threat_id = "2147926226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {db 45 fc 99 b9 64 00 00 00 f7 f9 83 ec 08 dd 1c 24 42}  //weight: 1, accuracy: High
        $x_1_2 = "windq.v3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_BSA_2147926248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.BSA!MTB"
        threat_id = "2147926248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 95 2c ff ff ff 8b c1 2b d1 81 fa 00 10 00 00 72 14 8b 49 fc 83 c2 23 2b c1 83 c0 fc 83 f8 1f 0f 87 d8 06 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_GA_2147927845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.GA!MTB"
        threat_id = "2147927845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shadow3dec_libvlc.dll" ascii //weight: 1
        $x_1_2 = "BITFUCKER" ascii //weight: 1
        $x_1_3 = "EDRMURDER" ascii //weight: 1
        $x_1_4 = "INVINSINCIBLE" ascii //weight: 1
        $x_1_5 = "CryptDecrypt" ascii //weight: 1
        $x_1_6 = "CryptDeriveKey" ascii //weight: 1
        $x_1_7 = "CryptDestroyKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_JT_2147927923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.JT!MTB"
        threat_id = "2147927923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 e8 00 00 00 00 5d 81 ed 10 00 00 00 81 ed c4 a2 9c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_BHB_2147927999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.BHB!MTB"
        threat_id = "2147927999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f 3a 2b 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_BKL_2147928026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.BKL!MTB"
        threat_id = "2147928026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f 44 2b 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_MBWH_2147928854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.MBWH!MTB"
        threat_id = "2147928854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 4d 24 00 60 97 24 00 05 00 b1 00 00 00 00 00 2c b3 98 7c ff ff ff ff 00 00 00 00 00 00 00 00 00 00 00 00 a0 0f 00 00 00 00 00 00 00 00 00 00 30 97 24 00 90 97 24 00 05 00 b1 00 00 00 00 00 2c b3 98 7c ff ff ff ff 00 00 00 00 00 00 00 00 00 00 00 00 a0 0f 00 00 00 00 00 00 00 00 00 00 60 97 24 00 a0 a7 24 00 01 02 b1 00 00 00 00 00 46 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 63 6f 6e 66 69 67 20 66 69 6c 65 3a 20 70 61 79 6c 6f 61 64 2e 69 6e 69 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NO_2147929606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NO!MTB"
        threat_id = "2147929606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 09 ff 89 59 08 80 61 24 80 8a 41 24 24 7f 88 41 24 66 c7 41 25 0a 0a 89 59 38 88 59 34 83 c1 40 89 4d dc}  //weight: 2, accuracy: High
        $x_1_2 = {d0 e5 d0 fd d0 c5 8a c5 24 0f d7 8a e0 d0 e1 d0 f9 d0 c1 8a c1 24 0f d7 d0 e4 d0 e4 0a c4}  //weight: 1, accuracy: High
        $x_1_3 = "NWVxNcTzPBkLzNrMdrvKwFlxXMXfEqNUmb" ascii //weight: 1
        $x_1_4 = "rFAQODRITNDpiCzvCHfVCtSSjkKzj" ascii //weight: 1
        $x_1_5 = "XpixvMajSoEhuKmchSSRy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fragtor_BB_2147931028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.BB!MTB"
        threat_id = "2147931028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 0c 08 8b 95 ?? ff ff ff [0-6] 31 d1 88 ca 8b 8d ?? ff ff ff 88 14 08 8b 85 ?? ff ff ff 83 c0 ?? 89 85 ?? ff ff ff e9}  //weight: 2, accuracy: Low
        $x_1_2 = "fdaskufhgbksuthlyijhrd" ascii //weight: 1
        $x_1_3 = "fghdftiyhsabfuDFERKF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_LLV_2147931124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.LLV!MTB"
        threat_id = "2147931124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 d0 0f af c3 bb cb ff ff ff 83 f0 a7 81 f6 d4 6d 01 00 a2 ?? ?? ?? ?? 69 c1 d4 6d 01 00 29 d6 81 f6 f7 16 0a e9 09 f8 0f af c3 bb cd ff ff ff 83 f0 02 a2 ?? ?? ?? ?? 89 d0 81 e2 d8 a4 fe ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_GKN_2147931261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.GKN!MTB"
        threat_id = "2147931261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c8 0f af c2 02 04 32 30 04 19 42 80 3c 32 00 75 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AUJ_2147931425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AUJ!MTB"
        threat_id = "2147931425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 0c 8b 4d 08 c7 45 ec 01 00 00 00 c7 45 f0 f4 ab 48 00 89 4d f4 89 45 f8 8d 45 ec 66 c7 45 fc 01 00 50 e8 61 0e ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_LS_2147932196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.LS!MTB"
        threat_id = "2147932196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 e8 00 00 00 00 5d 81 ed 10 00 00 00 81 ed ec c2 39 00 e9 04 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_MZP_2147932751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.MZP!MTB"
        threat_id = "2147932751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c0 8b d0 0f be c8 c1 ea 05 8a da 32 d0 22 d8 0f be d2 0f af d1 02 d8 22 da 32 d8 88 5c 04 ?? 40 3d 00 71 02 00 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_BU_2147932882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.BU!MTB"
        threat_id = "2147932882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 e0 08 89 45 c4 8b d8 0f b6 04 37 6a 04 8a 84 18 ?? ?? ?? ?? 30 04 32 46 58 3b f0 72}  //weight: 2, accuracy: Low
        $x_2_2 = {2b c1 8a 4d f3 8a 44 30 03 32 c1 88 44 37 03 83 c6 04 8b 43 04 40 c1 e0 04 3b f0 0f 82}  //weight: 2, accuracy: High
        $x_1_3 = {52 65 71 75 65 73 74 2e 64 6c 6c 00 63 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_JZP_2147932964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.JZP!MTB"
        threat_id = "2147932964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {32 c2 88 45 f3 8d 45 fc e8 f9 af f6 ff 8b 55 fc 8a 54 1a ff 80 e2 f0 8a 4d f3 02 d1 88 54 18 ff 46 8b 45 ?? e8 85 ad f6 ff 3b f0 7e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NR_2147933074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NR!MTB"
        threat_id = "2147933074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8a d9 88 5d e7 ff 75 dc e8 a5 05 00 00 59 e8 30 07 00 00 8b f0 33 ff 39 3e}  //weight: 3, accuracy: High
        $x_2_2 = {eb 05 8a d9 88 5d e7 ff 75 dc e8 a5 05 00 00 59 e8 30 07 00 00 8b f0 33 ff 39 3e 74 1b 56 e8 fd 04 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NFE_2147933279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NFE!MTB"
        threat_id = "2147933279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {56 ff 75 f8 89 45 fc 50 89 03 89 73 10 89 7b 14 e8 26 4e 00 00 8b 45 fc 83 c4 0c 5f c6 04 06 00 5e 5b 8b e5 5d}  //weight: 3, accuracy: High
        $x_1_2 = "amjsolutionx.pw/stub" ascii //weight: 1
        $x_1_3 = "SIDF.json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AAB_2147933404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AAB!MTB"
        threat_id = "2147933404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 c8 8a 00 88 c1 8b 45 ?? 88 c3 8b 45 ?? 01 d8 0f b6 c0 8d 1c 85 00 00 00 00 8b 45 ?? 01 d8 8b 00 31 c8 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_GNQ_2147933523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.GNQ!MTB"
        threat_id = "2147933523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 11 ?? ?? ?? ?? 33 f6 8b 55 ?? c1 e0 ?? 89 45 ?? 8b d8 0f b6 04 37 6a 04 8a 84 18 ?? ?? ?? ?? 30 04 32 46 58 3b f0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AAC_2147933719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AAC!MTB"
        threat_id = "2147933719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 e8 01 6a ?? 59 0f 48 c1 8a 4c 05 ?? 30 0c 13 42 3b 55 ?? 7c}  //weight: 4, accuracy: Low
        $x_1_2 = {4b 65 72 6e c7 45 ?? 65 6c 33 32 c7 45 ?? 2e 64 6c 6c 88 5d ?? c7 45 ?? 41 64 76 61 c7 45 ?? 70 69 33 32 c7 45 ?? 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_EN_2147934825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.EN!MTB"
        threat_id = "2147934825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {55 8b ec 8b 45 08 85 c0 78 0a 83 f8 1a 7d 0a 83 c0 41 5d c3}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_GVA_2147934994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.GVA!MTB"
        threat_id = "2147934994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 02 8d 52 01 c0 c8 04 8d 49 01 34 a5 46 88 41 ff 8b 45 44 03 c0 3b f0 72 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_GTK_2147935062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.GTK!MTB"
        threat_id = "2147935062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {94 d0 ff b7 8f 57 28 26 b4 0f}  //weight: 5, accuracy: High
        $x_5_2 = {0f 91 c7 31 2c 24 5b 45 3b ea 48}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_CCJU_2147935181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.CCJU!MTB"
        threat_id = "2147935181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\ProgramData\\Microsoft\\Program\\ziliao.jpg" ascii //weight: 2
        $x_2_2 = "C:\\ProgramData\\Microsoft\\EdgeUpdate\\Log\\chuangkou.log" ascii //weight: 2
        $x_1_3 = "\\shellcode\\" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_C_2147936278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.C!MTB"
        threat_id = "2147936278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 c1 e0 0d 33 c8 8b c1 c1 e0 11 33 c8 8b c1 c1 e0 05 33 c8}  //weight: 1, accuracy: High
        $x_1_2 = "Coran2.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_NMB_2147936500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.NMB!MTB"
        threat_id = "2147936500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c5 89 45 fc 33 c0 66 c7 45 e8 61 6e 66 89 45 de}  //weight: 1, accuracy: High
        $x_2_2 = {83 c4 18 84 c0 0f 94 c0 20 05 ?? ?? ?? ?? 8b 85 64 f5 ff ff 83 f8 08 72 13 40}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_PGF_2147939226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.PGF!MTB"
        threat_id = "2147939226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c8 c1 e9 1e 33 c8 69 c1 ?? ?? ?? ?? 03 c2 89 84 94 2c 01 00 00 42 81 fa 70 02 00 00 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_PGF_2147939226_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.PGF!MTB"
        threat_id = "2147939226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {66 0f a3 c8 0f bd c9 8a 06 66 f7 d1 30 d8 88 cd 60 fe c0 88 1c 24 0f 9b c1 d0 c8 8d 8b ?? ?? ?? ?? e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_PGF_2147939226_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.PGF!MTB"
        threat_id = "2147939226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 c1 83 e1 1f 0f b6 89 ?? ?? ?? ?? 30 0c 06 40 3d 00 9e 00 00 72 e9}  //weight: 5, accuracy: Low
        $x_5_2 = {89 c1 83 e1 1f 0f b6 89 ?? ?? ?? ?? 30 0c 07 40 3d 00 9e 00 00 75 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fragtor_AM_2147942012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AM!MTB"
        threat_id = "2147942012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 01 68 58 2a 47 00 ff 15 64 c1 45 00 8b d8 89 5d dc 85 db 0f 84 89 01 00 00 6a 00 68 00 01 00 80 6a 00 6a 00 68 80 2e 47 00 53 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_BAA_2147942112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.BAA!MTB"
        threat_id = "2147942112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b d0 31 13 83 45 ec 04 83 c3 04 8b 45 ec 3b 45 dc 72 92}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_BF_2147942905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.BF!MTB"
        threat_id = "2147942905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f b6 4c 24 0b 8b 14 85 ?? ?? ?? 00 0f b6 33 31 f1 88 4c 24 0b 83 fa 01 77}  //weight: 3, accuracy: Low
        $x_2_2 = {0f b6 4c 24 0b 32 4c 13 ff 88 4c 24 0b 8b 4c 24 0c 01 d1 89 4c 24 0c 89 f1 80 f9 4d 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_ZIN_2147943679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.ZIN!MTB"
        threat_id = "2147943679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b7 c9 33 ca 89 1d ?? ?? ?? ?? 89 4c 24 54 8b 4c 24 28 d3 e7 89 7c 24 38 8b 7c 24 60 8b 94 24 98 00 00 00 8b 44 24 40 05 69 21 00 00 89 84 24 a8 00 00 00 8b 44 24 5c 0f af 44 24 20 89 44 24 5c 66 a3 ?? ?? ?? ?? 8b 84 24 84 00 00 00 0f b7 c0 39 44 24 38 7d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_ARAX_2147943931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.ARAX!MTB"
        threat_id = "2147943931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 c2 0f b7 05 ?? ?? ?? ?? 0f b7 0d ?? ?? ?? ?? 66 0f ac c1 ?? 89 c8 35 ?? ?? ?? ?? 66 89 46 18 89 d1}  //weight: 2, accuracy: Low
        $x_2_2 = "GetFileVersionInfoW" ascii //weight: 2
        $x_2_3 = "GetFileVersionInfoSizeW" ascii //weight: 2
        $x_2_4 = "VerQueryValueW" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_MR_2147944554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.MR!MTB"
        threat_id = "2147944554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Fe3048124832f0cef883941e6035e2bbbc237.exe" ascii //weight: 50
        $x_25_2 = {28 ad c0 14 83 c0 04 eb 0b dd 35 e9 48 a8 46 a1 9e 6a ec 23 83 ea 01 f9 72}  //weight: 25, accuracy: High
        $x_25_3 = {1f 93 ee 29 42 8a 27 67 13 bb ed 45 28 ad c0 14 83 c0}  //weight: 25, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_SPB_2147944908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.SPB!MTB"
        threat_id = "2147944908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {88 1c 08 89 4a 04 33 c0 40 8b 95 ?? ?? ff ff 03 f8 e9}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AO_2147945016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AO!MTB"
        threat_id = "2147945016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 56 57 56 81 e6 b8 37 00 00 81 ce fe 4b 00 00 81 e6 1d 61 01 00 81 ee 00 21 00 00 5e 50 50 83 c4 04 81 e8 4b 46 00 00 81 f0 4e 0e 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_LM_2147945893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.LM!MTB"
        threat_id = "2147945893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {8a 95 e7 ef ff ff 2a d0 8b 85 18 f0 ff ff 02 d1 30 17 83 c0 21 3b 85 14 f0 ff ff 7e ?? ff 8d 0c f0 ff ff 3b c6 7c ?? 8b d6 d1 ea 2b d6 03 d0 8d 7c 0a 05 eb}  //weight: 15, accuracy: Low
        $x_10_2 = {83 fa 67 75 ?? 8d 4c 00 01 8b d0 d3 e2 8d 48 01 85 c9 7e ?? 8d 49 00 0f af d0 03 d2 03 d2 03 d2 49 75 f4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_LM_2147945893_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.LM!MTB"
        threat_id = "2147945893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {c6 44 24 19 24 c6 44 24 1a 74 [0-7] c6 44 24 1b 72 c6 44 24 1c 69 [0-5] c6 44 24 1d 67 c6 44 24 1e 67 c6 44 24 1f 65 c6 44 24 20 72}  //weight: 20, accuracy: Low
        $x_10_2 = {0f b6 84 14 7c 01 00 00 88 04 17 83 c2 01 83 fa ?? ?? ?? 89 7c 24 04 89 34 24 c6 84 24 be 04 00 00 00}  //weight: 10, accuracy: Low
        $x_5_3 = {c6 44 24 26 53 c6 44 24 27 63 c6 44 24 28 68 c6 44 24 29 65 c6 44 24 2a 64 c6 44 24 2b 75 c6 44 24 2c 6c ?? ?? ?? ?? ?? ?? c6 44 24 2d 65 c6 44 24 2e 64}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AG_2147945970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AG!MTB"
        threat_id = "2147945970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0c 27 23 c0 33 cb 66 25 10 91 8b d0 41 42 0f 8c 01 99 eb ff 48 c7 44 24 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AI_2147945977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AI!MTB"
        threat_id = "2147945977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 04 00 00 00 8d 4d c8 c7 45 e0 00 00 00 00 2b ce c7 45 e4 00 00 00 00 b8 ?? ?? ?? ?? c7 45 e8 00 00 00 00 f7 e9 c1 fa 02 8b c2 c1 e8 1f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_KK_2147946088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.KK!MTB"
        threat_id = "2147946088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {28 ad c0 14 83 c0 04 eb 0b dd 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 ea 01 f9 72}  //weight: 8, accuracy: Low
        $x_7_2 = {83 2f 01 f9 72 0b 2f e3 ?? 09 c0 4b 8a 5b af 0c d7}  //weight: 7, accuracy: Low
        $x_5_3 = "Fe3048124832f0cef883941e6035e2bbbc237.exeFe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AHB_2147948328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AHB!MTB"
        threat_id = "2147948328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {6a 6c 6a 6c 6a 64 6a 2e 6a 32 6a 33 6a 6c 53 6a 6e 6a 72 53 6a 6b 8d 85 ec fe ff ff}  //weight: 20, accuracy: High
        $x_30_2 = {8d 45 f4 50 8d 85 ec ee ff ff 68 ?? ?? ?? ?? 50 ff 55 f8 85 c0 75}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_GVC_2147950103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.GVC!MTB"
        threat_id = "2147950103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c6 c1 e8 1e 33 c6 69 f0 ?? ?? ?? ?? 03 f1 89 b4 8d 24 ec ff ff 41 81 f9 70 02 00 00 72 e1}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 5d f4 8d 04 0b 8b 4d fc 35 ?? ?? ?? ?? 8a 44 05 a8 88 04 31 41 89 4d fc 83 f9 14 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_GVD_2147950104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.GVD!MTB"
        threat_id = "2147950104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 5c 24 18 8d 04 0b 8b 4c 24 10 35 00 00 00 80 8a 44 04 28 88 04 31 41 89 4c 24 10 83 f9 14 0f 82 78 ff ff ff}  //weight: 2, accuracy: High
        $x_1_2 = {8b 86 b8 00 00 00 8b 96 b4 00 00 00 8d 48 01 3b d1 75 10 fe c0 30 86 be 00 00 00 ff 86 b4 00 00 00 eb dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AR_2147954447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AR!MTB"
        threat_id = "2147954447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 46 04 03 c1 8b 4d b4 03 d0 41 8b 45 b4 83 e0 03 89 4d b4 8a 44 05 d0 30 02 33 c0 8b 55 b8 3b cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_MK_2147954933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.MK!MTB"
        threat_id = "2147954933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {b8 8e 01 00 00 2b c6 8d 7e 01 0f af c7 c1 e0 04 03 d8 ff 85 b0 f8 ff ff 8b 85 a0 f8 ff ff}  //weight: 15, accuracy: High
        $x_10_2 = {8a 8d a7 f8 ff ff 8b 95 c0 f8 ff ff 88 0c 10 8b 8d 90 f8 ff ff 8a 54 08 01 8b 8d c0 f8 ff ff 88 54 08 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_MKA_2147955147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.MKA!MTB"
        threat_id = "2147955147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {89 c7 c6 44 24 ?? 24 c6 44 24 ?? 74 c6 44 24 ?? 72 c6 44 24 ?? 69 c6 44 24 ?? 67 c6 44 24 ?? 67 c6 44 24 ?? 65 c6 44 24 ?? 72 f3 a5 c6 44 24 ?? 3d c6 44 24}  //weight: 15, accuracy: Low
        $x_10_2 = {53 8d bc 24 ?? 01 00 00 c6 44 24 ?? 63 c6 44 24 ?? 68 c6 44 24 ?? 65 c6 44 24 ?? 64 c6 44 24 ?? 75 c6 44 24 ?? 6c c6 44 24 ?? 65 c6 44 24 ?? 64 c6 44 24}  //weight: 10, accuracy: Low
        $x_5_3 = {0f b6 84 0c ?? 01 00 00 88 04 0f 83 c1 01 83 f9 76 ?? ?? 89 7c 24 04 89 34 24 89 54 24 1c c6 84 24 c6 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_LMC_2147955370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.LMC!MTB"
        threat_id = "2147955370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {c6 45 e3 00 c6 45 f2 34 c6 45 f3 00 c6 45 d4 25 c6 45 d5 73 c6 45 d6 5c c6 45 d7 25 c6 45 d8 63 c6 45 d9 25 c6 45 da 63 c6 45 db 25 c6 45 dc 63 c6 45 dd 25 c6 45 de 63 c6 45 df 00}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_BAB_2147955837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.BAB!MTB"
        threat_id = "2147955837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b f0 8b 45 dc 31 30 83 c3 04 83 45 dc 04 3b 5d d8 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_SMN_2147956671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.SMN!MTB"
        threat_id = "2147956671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e0 05 33 f0 b8 ?? ?? ?? ?? f7 e6 8b c8 b8 25 49 92 24 f7 e6 b8 ?? ?? ?? ?? 03 ca f7 e6 8b c6 d1 e9 2b c2 83 e1 ?? d1 e8 03 c2 c1 e8 03 2b c1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_CBK_2147956689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.CBK!MTB"
        threat_id = "2147956689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 58 58 f9 f8 83 f7 ?? f9 f8 83 45 ?? ?? 8d 85 ?? ?? ff ff 89 44 24 ?? 8b 45 ?? 89 04 24 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_BAC_2147957282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.BAC!MTB"
        threat_id = "2147957282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 10 33 da 8b 45 fc 50 8b 4d 08 e8 ?? ?? ?? ?? 88 18 eb}  //weight: 2, accuracy: Low
        $x_1_2 = "cmd /c timeout /t 5 > nul && del" ascii //weight: 1
        $x_1_3 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AHC_2147957306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AHC!MTB"
        threat_id = "2147957306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {58 6a 20 66 89 45 ce 58 6a 69 66 89 45 d0 58 6a 6c 66 89 45 d4 58 6a 65 66 89 45 d6 58 6a 73 66 89 45 d8}  //weight: 30, accuracy: High
        $x_20_2 = {0f b6 c1 8a 4c 3b ?? 0f 43 d0 c0 e2 ?? ?? ?? ?? 57 1a c0 83 c3 ?? 24 ?? 04 ?? 2a c8 02 ca 88 0e 46}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_GVE_2147957333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.GVE!MTB"
        threat_id = "2147957333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4c 24 08 8b 44 24 04 8a 09 32 08 88 08}  //weight: 2, accuracy: High
        $x_1_2 = {8b 4c 24 5c 8b 84 24 bc 01 00 00 89 44 24 4c 8b 54 24 78 89 c6 03 74 24 7c 89 74 24 50 8a 14 02 88 54 24 57 39 c8 73 17 8b 44 24 50 8b 54 24 58 8b 74 24 4c 8a 4c 24 57 32 0c 32 88 08 eb 97}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_SXA_2147957566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.SXA!MTB"
        threat_id = "2147957566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {50 ff d3 85 c0 74 f3 6a ?? 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50 ff d7 85 c0 75 09 68 ?? ?? ?? ?? ff d6 eb d4}  //weight: 30, accuracy: Low
        $x_15_2 = {50 ff d7 68 e8 03 00 00 ff d6 8d 85 ?? ?? ?? ?? 50 ff d3 85 c0 75 e3}  //weight: 15, accuracy: Low
        $x_5_3 = {2b f9 d1 ff 8b c7 8b cf 99 83 e2 ?? 03 c2 c1 f8 ?? 2b c8 83 c1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_AB_2147957586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.AB!MTB"
        threat_id = "2147957586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {83 c7 0c 83 c3 f4 84 c9 75 73 85 db 0f 84 85 00 00 00 8b 47 04 8b 77 08 8d 4d e0 ba ?? ?? ?? ?? 89 45 f0 68 ?? ?? ?? ?? 6a 19 e8 ?? ?? ?? ?? 83 c4 08 8b 45 e4 3b 75 e8 75 26 56 89 c6 50 ff 75 f0 e8 ?? ?? ?? ?? 83 c4 0c 85 c0 0f 94 c1 8b 45 e0 85 c0 75 16 eb a9}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_MCP_2147958548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.MCP!MTB"
        threat_id = "2147958548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 d2 43 00 01 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 e4 cc 43 00 ac cc 43 00 84 42 40 00 78 00 00 00 82 00 00 00 8b 00 00 00 8c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 73 6f 70 72 61 6e 69 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_ARR_2147958669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.ARR!MTB"
        threat_id = "2147958669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "LoadmyDll" ascii //weight: 6
        $x_4_2 = "strat run" ascii //weight: 4
        $x_10_3 = "IOJCMain" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_ARR_2147958669_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.ARR!MTB"
        threat_id = "2147958669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {0f 10 23 0f 10 6b ?? 0f 57 e0 0f 57 e9 0f 11 20 0f 11 68}  //weight: 8, accuracy: Low
        $x_6_2 = {f7 e1 8d 8e ?? ?? ?? ?? 89 d0 89 fa d1 e8 66 83 7e}  //weight: 6, accuracy: Low
        $x_4_3 = {f7 e1 8b 46 ?? 89 d7 89 c1 f7 66}  //weight: 4, accuracy: Low
        $x_2_4 = "FromUtf8ErrorbytesNulMutexError~\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_LME_2147958751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.LME!MTB"
        threat_id = "2147958751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {b0 01 84 c0 79 ?? 81 c2 00 58 47 f8 89 54 24 08 83 d1 0d 89 4c 24 0c}  //weight: 20, accuracy: Low
        $x_10_2 = {8b 4d e4 83 c4 0c 8b 45 dc 03 c0 c6 45 ef 01 89 71 30 66 89 41 2c 66 89 79 2e 8b 4d e0 83 f9 07}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_PBK_2147958775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.PBK!MTB"
        threat_id = "2147958775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 04 0a 8d 49 ?? 32 c3 2a 85 ?? ?? ?? ?? 88 41 ?? 83 ee ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_PGFR_2147958778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.PGFR!MTB"
        threat_id = "2147958778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 d2 f7 75 14 8b 45 d4 0f b6 0c 11 31 c8 88 45 df 83 3d ?? ?? ?? ?? 00 74 ?? 8a 55 df a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 ce 83 c6 01 89 35 ?? ?? ?? ?? 88 14 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_SXB_2147959486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.SXB!MTB"
        threat_id = "2147959486"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\1.dll" ascii //weight: 3
        $x_3_2 = "BLACKLIST_IP||" ascii //weight: 3
        $x_3_3 = "MD5_DETECT||" ascii //weight: 3
        $x_2_4 = "BLACKLIST_DATA" ascii //weight: 2
        $x_2_5 = "blacklist.dat" ascii //weight: 2
        $x_1_6 = "svchost.exe" ascii //weight: 1
        $x_1_7 = "winlogon.exe" ascii //weight: 1
        $x_1_8 = "taskmgr.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fragtor_SXC_2147959487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fragtor.SXC!MTB"
        threat_id = "2147959487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {89 c8 f7 e7 c1 ea 04 6b c2 ?? 8d 14 2e 0f b6 5c 2e ?? 32 5c 10 ?? 8b 44 24 ?? 88 5c 28 ?? 41 45 75 de}  //weight: 20, accuracy: Low
        $x_10_2 = {89 34 24 c7 44 24 ?? ?? ?? 00 00 c7 44 24 ?? ?? ?? 00 00 ff 15 ?? ?? ?? ?? eb 0c b9 ff ff ff ff eb 10 b8 ff ff ff ff 89 c6 57 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

