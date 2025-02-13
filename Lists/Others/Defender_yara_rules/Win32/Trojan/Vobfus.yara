rule Trojan_Win32_Vobfus_C_2147651004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vobfus.C"
        threat_id = "2147651004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /im" wide //weight: 1
        $x_2_2 = "D:\\SD_GEN\\downloader\\downloadergg\\vb6\\VB6.OLB" ascii //weight: 2
        $x_2_3 = "BlockDecrypt" ascii //weight: 2
        $x_1_4 = "vbexeList1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vobfus_DEA_2147761738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vobfus.DEA!MTB"
        threat_id = "2147761738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 d3 e0 03 fb c1 eb 05 03 9d ?? fd ff ff 03 85 ?? fd ff ff 89 bd ?? fd ff ff 89 45 f8 8b 85 ?? fd ff ff 31 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vobfus_2147809627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vobfus.ffhh!MTB"
        threat_id = "2147809627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "ffhh: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "emgkgtgnnmnmninigthkgogggvmkhinjggnvm" ascii //weight: 2
        $x_2_2 = "swkrqbwb" ascii //weight: 2
        $x_2_3 = "gzggyfewmegxiv" ascii //weight: 2
        $x_2_4 = "uyvtvwfekdu" ascii //weight: 2
        $x_2_5 = "hjrhvkgfaejhy" ascii //weight: 2
        $x_2_6 = "xempoq" ascii //weight: 2
        $x_2_7 = "qloijpgb" ascii //weight: 2
        $x_2_8 = "tcbtntu" ascii //weight: 2
        $x_2_9 = "\\gfx\\shotp.bmp" ascii //weight: 2
        $x_2_10 = "qthqvpbi.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vobfus_BD_2147836913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vobfus.BD!MTB"
        threat_id = "2147836913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 73 63 00 3a 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 46 6f 72}  //weight: 1, accuracy: High
        $x_1_2 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS\\UCKH" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vobfus_BE_2147837293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vobfus.BE!MTB"
        threat_id = "2147837293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a5 58 2f ed a2 4d 98 21 e6 42 3c de bb 2d 6b 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 4c}  //weight: 1, accuracy: High
        $x_1_2 = {85 55 42 1c 84 46 ad bb 7d 93 aa 54 5a 35 00 77 12 3a 56 fa 69 49 87 86 e5 fc bd d0 96 b0 e7 e5 b0 5a 7e 64 69 43 80 cd 97 c3 1f 21 d5 16 71}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vobfus_BK_2147852482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vobfus.BK!MTB"
        threat_id = "2147852482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 60 48 3f 46 ee af 95 40 b5 87 84 e6 2f 2a 98 4e 2a 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71}  //weight: 1, accuracy: High
        $x_1_2 = {39 dd 2b 93 53 64 91 21 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 43 6c 61 73}  //weight: 1, accuracy: High
        $x_1_3 = {04 05 4c 91 e3 cf 5c b2 90 c3 d0 62 55 6d 33 a8 ef 2e 48 8c b3 c5 c0 fc 7a 7d}  //weight: 1, accuracy: High
        $x_1_4 = {3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 22 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 02 00 00 00 0c 5d 40 00 1c 5d 40 00 00 00 00 00 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vobfus_MBFH_2147898359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vobfus.MBFH!MTB"
        threat_id = "2147898359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 00 28 30 41 00 1c 81 40 00 dc 8e 40 00 20 6f 40 00 44 6f 40}  //weight: 1, accuracy: High
        $x_1_2 = {71 40 00 00 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 3c 6a 40 00 3c 6a 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vobfus_MBYK_2147915220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vobfus.MBYK!MTB"
        threat_id = "2147915220"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f8 26 40 00 d8 15 40 00 10 f1 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 01 00 e9 00 00 00 30 12 40 00 c8 13 40 00 70 11 40 00 78 00 00 00 7f 00 00 00 89 00 00 00 8a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vobfus_MBXW_2147925117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vobfus.MBXW!MTB"
        threat_id = "2147925117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vobfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 2f 41 00 2c 39 40 00 12 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 01 00 e9 00 00 00 00 37 40 00 e4 37 40 00 74 36 40 00 78 00 00 00 81 00 00 00 8a 00 00 00 8b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

