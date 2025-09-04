rule Trojan_MSIL_Marsilia_GNC_2147850670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.GNC!MTB"
        threat_id = "2147850670"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {13 05 11 04 17 59 13 04 2b 23 08 2d 20 06 11 05 02 7b 21 00 00 04 11 06 91 09 17 59 1f 1f 5f 63 20 ff 00 00 00 09 1f 1f 5f 63 5f d2 9c 11 06 15 58 13 06 11 06 03 2f 87}  //weight: 10, accuracy: High
        $x_1_2 = "nnjnnml.github.io" ascii //weight: 1
        $x_1_3 = "\\browserPasswords" ascii //weight: 1
        $x_1_4 = "encrypted_key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_KAA_2147850830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.KAA!MTB"
        threat_id = "2147850830"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {72 01 00 00 70 28 03 00 00 06 72 0d 00 00 70 28 02 00 00 06 0a 28 04 00 00 0a 0b 72 19 00 00 70 28 05 00 00 0a 0c 1f 0a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMAA_2147852132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMAA!MTB"
        threat_id = "2147852132"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" ascii //weight: 1
        $x_1_2 = "ComputeHash" ascii //weight: 1
        $x_1_3 = "U0VMRUNUICogRlJPTSBBbnRpdmlydXNQcm9kdWN0" wide //weight: 1
        $x_1_4 = "01daefe4caf17be6854e1a9a0dece70c" wide //weight: 1
        $x_1_5 = "2793405ebfdtrXCIOVNT<ERKEY" wide //weight: 1
        $x_1_6 = "Defender cool select" wide //weight: 1
        $x_1_7 = "XHJvb3RcU2VjdXJpdHlDZW50ZXIy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMAB_2147853388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMAB!MTB"
        threat_id = "2147853388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2b 0b 03 1f 10 28 ?? 00 00 2b 28 ?? 00 00 2b 0c 06 02 07 6f ?? 00 00 0a 0d 09 08 16 08 8e 69 6f ?? 00 00 0a 13 04 11 04 13 05 dd}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMAB_2147853388_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMAB!MTB"
        threat_id = "2147853388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Main process, start persistence process" ascii //weight: 1
        $x_1_2 = "cryptercore1" ascii //weight: 1
        $x_1_3 = "svchost.exe" ascii //weight: 1
        $x_1_4 = "Writing registry key" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "Error checking ActiveProcessCount for killed process:" ascii //weight: 1
        $x_1_7 = "Already have an existing process, dont start process, count:" ascii //weight: 1
        $x_1_8 = "SELECT * FROM __InstanceOperationEvent WITHIN  1 WHERE TargetInstance" ascii //weight: 1
        $x_1_9 = "file.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_ARIT_2147888626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.ARIT!MTB"
        threat_id = "2147888626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 17 d6 0b 07 19 d6 0b 07 18 da 0b 07 20 a0 86 01 00 33 ec 16 0c 08 17 d6 0c 17 0d 09 1b d6 1b d6 18 d6 0d 08 20 88 13 00 00 33 06 08 17 d6 17 da 0c 09 09 08 d6 1b da d6 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_APN_2147888777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.APN!MTB"
        threat_id = "2147888777"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 72 15 00 00 70 6f ?? ?? ?? 0a 07 72 29 00 00 70 6f ?? ?? ?? 0a 07 72 e4 03 00 70 6f ?? ?? ?? 0a 07 72 f8 03 00 70 6f ?? ?? ?? 0a 07 72 1c 04 00 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AAMP_2147888808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AAMP!MTB"
        threat_id = "2147888808"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 3c 08 00 70 28 ?? ?? 00 06 1c 2d 1c 26 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 01 00 06 1b 2d 06 26 de 09 0a 2b e2 0b 2b f8 26 de cd}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AC_2147892104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AC!MTB"
        threat_id = "2147892104"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 07 16 08 6e 28 ?? ?? ?? 0a 07 8e 69 28 ?? ?? ?? 0a 00 7e 12 00 00 0a 0d 16 13 04 7e 12 00 00 0a 13 05 16 16 08 11 05 16 12 04 28 ?? ?? ?? 06 0d 09 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMAD_2147892240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMAD!MTB"
        threat_id = "2147892240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 06 07 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0c 02 0d 08 09 16 09 8e b7 6f ?? 00 00 0a 13 04 dd ?? 00 00 00 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_KAB_2147894565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.KAB!MTB"
        threat_id = "2147894565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e9 9a 86 e5 92 8c 00 e5 ae 9d e9 9a 86 e5 92 8c 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 53 00 79 00 73 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 2e 00 64 00 6c 00 6c}  //weight: 1, accuracy: High
        $x_1_3 = "My.Program" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_KAC_2147894566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.KAC!MTB"
        threat_id = "2147894566"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 08 11 04 02 11 04 91 07 61 06 09 91 61 28 ?? 00 00 0a 9c 09 03 6f ?? 00 00 0a 17 59 fe 01 13 05 11 05 2c 06 00 16 0d 00 2b 06 00 09 17 58 0d 00 00 11 04 17 58 13 04 11 04 02 8e 69 fe 04 13 06 11 06 2d 02 2b 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_PTBA_2147895524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.PTBA!MTB"
        threat_id = "2147895524"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 13 00 00 0a 14 28 ?? 00 00 0a 2d 03 14 2b 0b 07 6f 13 00 00 0a 28 ?? 00 00 0a 0c 07 08 14 6f 16 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_PTBC_2147895542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.PTBC!MTB"
        threat_id = "2147895542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 e2 00 00 70 0b 06 7e 01 00 00 04 72 01 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 00 07 16 28 ?? 00 00 0a 72 73 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 00 72 8f 01 00 70 0c 08 28 ?? 00 00 06 0d 09 2c 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_PTBP_2147895890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.PTBP!MTB"
        threat_id = "2147895890"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2c 42 02 7b 10 00 00 04 72 d9 01 00 70 6f 24 00 00 0a 6f 25 00 00 0a 0c 12 02 28 ?? 00 00 0a 2d 3f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_PTBR_2147896163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.PTBR!MTB"
        threat_id = "2147896163"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 2c 42 02 7b 10 00 00 04 72 d9 01 00 70 6f 25 00 00 0a 6f 26 00 00 0a 0c 12 02 28 ?? 00 00 0a 2d 3f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_PTBV_2147896533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.PTBV!MTB"
        threat_id = "2147896533"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 0c 28 ?? 00 00 0a 11 0d 28 ?? 00 00 0a 6f 24 00 00 0a a2 2b 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_NM_2147896733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.NM!MTB"
        threat_id = "2147896733"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 6f 55 00 00 0a 08 16 28 ?? ?? 00 0a 0d 06 72 ?? ?? 00 70 09 72 ?? ?? 00 70 6f ?? ?? 00 0a 5e 6f ?? ?? 00 0a 6f ?? ?? 00 0a 26 02 25 17 59 10 00 16 30 cb}  //weight: 5, accuracy: Low
        $x_1_2 = "ciao-decrypter.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_NM_2147896733_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.NM!MTB"
        threat_id = "2147896733"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TaiLieuJX" ascii //weight: 2
        $x_2_2 = "AutoKeoXe.exe" wide //weight: 2
        $x_2_3 = "AntiVolam.ini" wide //weight: 2
        $x_1_4 = "XungBaGiangHo.Com" ascii //weight: 1
        $x_1_5 = "$9f0251fb-b749-412c-928a-841667662226" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_NMA_2147896736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.NMA!MTB"
        threat_id = "2147896736"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 73 0d 00 70 28 ?? ?? 00 0a 6f af 00 00 0a 6f ?? ?? 00 0a 73 76 00 00 0a 6f ?? ?? 00 0a 0a 06 72 ?? ?? 00 70 28 1b 00 00 0a 2c 17 72 ?? ?? 00 70 72 c7 0d 00 70 28 ?? ?? 00 0a 26 28}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_PTCU_2147897538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.PTCU!MTB"
        threat_id = "2147897538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 16 11 05 6f 45 00 00 0a 07 11 04 16 11 04 8e 69 6f 3e 00 00 0a 13 05 11 05 16 30 db}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMR_2147899662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMR!MTB"
        threat_id = "2147899662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 1f 10 0b 07 28 ?? 00 00 06 68 0c 08 20 00 80 00 00 5f 20 00 80 00 00 fe 01 13 05 11 05 2c 04 00 17 0a 00 28 ?? 00 00 0a 0d 06 09 60 13 04 11 04 13 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMR_2147899662_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMR!MTB"
        threat_id = "2147899662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 08 2b 3b 11 07 11 08 9a 13 09 11 05 11 09 6f ?? 00 00 0a 13 0a 12 0a 28 ?? 00 00 0a 58 13 05 11 06 11 09 6f ?? 00 00 0a 13 0a 12 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 13 06 11 08 17 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMR_2147899662_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMR!MTB"
        threat_id = "2147899662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 00 02 0b 16 0c 2b 1a 07 08 91 0d 06 72 70 0a 00 70 09 8c 6f 00 00 01 6f ?? 00 00 0a 26 08 17 58 0c 08 07 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = "test_aimbot.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMR_2147899662_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMR!MTB"
        threat_id = "2147899662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 09 2b 20 11 08 11 09 9a 13 0a 00 00 00 de 0d 26 00 11 0a 6f ?? 00 00 0a 00 00 de 00 00 11 09 17 58 13 09 11 09 11 08 8e 69 32 d8}  //weight: 2, accuracy: Low
        $x_1_2 = "HypixelSkyblockDupe.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMI_2147900185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMI!MTB"
        threat_id = "2147900185"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 00 06 0b 16 0c 2b 27 07 08 9a 0d 00 09 6f 36 00 00 0a 72 01 00 00 70 1b 6f 37 00 00 0a 13 04 11 04 2c 06 00 17 13 05 2b 10 00 08 17 58 0c 08 07 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMI_2147900185_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMI!MTB"
        threat_id = "2147900185"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 9a 16 9a 7e ?? 00 00 04 20 ?? bd 66 06 28 ?? 00 00 06 28 ?? 00 00 0a 2d 11 06 08 9a 16 9a 28 ?? 00 00 06 28 ?? 00 00 0a 2b 05 28 ?? 00 00 0a 06 08 9a 17 9a 28 ?? 00 00 06 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_PTEQ_2147900243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.PTEQ!MTB"
        threat_id = "2147900243"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 01 00 00 04 72 8d 00 00 70 73 12 00 00 0a 28 ?? 00 00 0a 72 e5 00 00 70 28 ?? 00 00 0a 6f 15 00 00 0a 00 2b 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_PTFA_2147900410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.PTFA!MTB"
        threat_id = "2147900410"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 a2 07 00 70 0a 06 28 ?? 01 00 0a 0b 28 ?? 01 00 0a 25 26 07 16 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMA_2147900528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMA!MTB"
        threat_id = "2147900528"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 06 17 6f ?? 00 00 0a 06 02 16 9a 6f ?? 00 00 0a 06 17 6f ?? 00 00 0a 25 06 6f ?? 00 00 0a 06 02 17 9a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMA_2147900528_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMA!MTB"
        threat_id = "2147900528"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 04 2b 2f 07 16 28 ?? 00 00 0a 73 28 00 00 0a 05 11 04 94 28 ?? 00 00 0a 0d 02 7b 13 00 00 04 09 07 07 8e 69 12 02 28 ?? 00 00 06 26 11 04 17 58 13 04 11 04 05 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_PTFN_2147900701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.PTFN!MTB"
        threat_id = "2147900701"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 7d 00 00 70 72 57 00 00 70 6f 17 00 00 0a 00 72 57 00 00 70 28 ?? 00 00 0a 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_PTGD_2147900860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.PTGD!MTB"
        threat_id = "2147900860"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 1a 00 00 01 0a 03 28 ?? 00 00 0a 0b 28 ?? 00 00 0a 0c 08 28 ?? 00 00 0a 02 6f 26 00 00 0a 6f 27 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_PTGI_2147900959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.PTGI!MTB"
        threat_id = "2147900959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 01 00 00 04 72 71 00 00 70 73 12 00 00 0a 28 ?? 00 00 0a 72 c5 00 00 70 28 ?? 00 00 0a 6f 15 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMCC_2147901626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMCC!MTB"
        threat_id = "2147901626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 0f 11 11 11 12 61 11 13 11 0d 5d 59 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_MMC_2147901629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.MMC!MTB"
        threat_id = "2147901629"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 28 02 00 00 06 28 06 00 00 06 2a}  //weight: 2, accuracy: High
        $x_1_2 = {53 6c 69 76 [0-15] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMBG_2147902013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMBG!MTB"
        threat_id = "2147902013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9e 06 06 08 94 06 09 94 58 20 00 01 00 00 5d 94 13 ?? 11 ?? 11 ?? 03 11 ?? 91 11 ?? 61 28 ?? ?? ?? ?? 9c 00 11 ?? 17 58 13 ?? 11 ?? 03 8e 69 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_NA_2147902548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.NA!MTB"
        threat_id = "2147902548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {13 07 11 07 2c 0c 00 11 05 1a 5a 11 06 58 13 04}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_NA_2147902548_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.NA!MTB"
        threat_id = "2147902548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encryptedBytes" ascii //weight: 1
        $x_1_2 = "decryptedText" ascii //weight: 1
        $x_1_3 = "MSOfficeRunOncelsls" ascii //weight: 1
        $x_1_4 = "deletevalue {default} safeboot" ascii //weight: 1
        $x_1_5 = "C:\\Windows\\Help" ascii //weight: 1
        $x_1_6 = "C:\\Windows\\Help\\Pay.txt" ascii //weight: 1
        $x_1_7 = "ThisIsStage2" ascii //weight: 1
        $x_1_8 = "root\\WMI:BcdObject.Id=" ascii //weight: 1
        $x_1_9 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_FKAA_2147903198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.FKAA!MTB"
        threat_id = "2147903198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 0b 2b 13 06 07 02 07 91 04 07 04 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 6a 03 32 e8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_SPCJ_2147903225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.SPCJ!MTB"
        threat_id = "2147903225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 8e 69 20 ?? ?? ?? 00 1f 40 28 ?? ?? ?? 06 0d 7e ?? ?? ?? 0a 13 ?? 07 7b ?? ?? ?? 04 09 06 06 8e 69 12 ?? 28 ?? ?? ?? 06 2c 1e 16}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_SPVG_2147903227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.SPVG!MTB"
        threat_id = "2147903227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {09 02 8e 69 17 58 11 04 58 18 28 ?? ?? ?? 06 20 ?? ?? ?? 00 28 ?? ?? ?? 0a d2 9c 11 04 17 58 13 04}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMS_2147904356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMS!MTB"
        threat_id = "2147904356"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 0b 00 1f 0d 02 07 6f 11 00 00 0a 28 05 00 00 06 16 28 02 00 00 06 0c de 16 07 2c 07 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMS_2147904356_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMS!MTB"
        threat_id = "2147904356"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 2b 4c 06 6f ?? 00 00 0a 74 16 00 00 01 0b 18 8d 18 00 00 01 25 16 7e 26 00 00 0a a2 25 17 7e 26 00 00 0a a2 0c 07 72 99 00 00 70 08 0d 09 6f ?? 00 00 0a 28 ?? 00 00 0a 2d 14 08 17 9a 72 ab 00 00 70 08 16 9a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AMMD_2147905415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AMMD!MTB"
        threat_id = "2147905415"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 13 0b 73 ?? 00 00 0a 11 0b 72 ?? ?? 00 70 07 28 ?? 00 00 0a 6f ?? 00 00 0a 11 0b 6f ?? 00 00 0a 6f ?? 00 00 0a 25 28 ?? 00 00 0a 13 0c 72 ?? ?? 00 70 28 ?? 00 00 06 16 8d ?? 00 00 01 28 ?? 00 00 06 72}  //weight: 2, accuracy: Low
        $x_1_2 = "{1}[19][19][5][13][2][12][25]" ascii //weight: 1
        $x_1_3 = "{12}[15][1][4]" ascii //weight: 1
        $x_1_4 = "{5}[14][20][18][25]{16}[15][9][14][20]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_KAD_2147905525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.KAD!MTB"
        threat_id = "2147905525"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 9a 13 06 06 1f 0c 28 ?? 00 00 0a 6a 02 58 09 18 5a 6a 58 28 ?? 00 00 0a 18 28 ?? 00 00 06 16 28 ?? 00 00 0a 13 07 11 06 25 2d 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_KAE_2147906005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.KAE!MTB"
        threat_id = "2147906005"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 08 02 08 93 06 08 06 8e 69 5d 93 61 d1 9d 08 17 58 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_KAF_2147906036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.KAF!MTB"
        threat_id = "2147906036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 08 02 08 93 06 08 06 8e 69 5d 93 61 d1 9d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_SG_2147906260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.SG!MTB"
        threat_id = "2147906260"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 20 00 00 0a 11 05 6f 23 00 00 0a 13 09 11 09 28 0a 00 00 06 13 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_SXXP_2147908217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.SXXP!MTB"
        threat_id = "2147908217"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0b 02 72 17 00 00 70 72 1b 00 00 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0c 28 ?? ?? ?? 0a 07 08 16 08 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 2b 00}  //weight: 4, accuracy: Low
        $x_1_2 = "HypixelSkyblockDupe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_SPFV_2147909807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.SPFV!MTB"
        threat_id = "2147909807"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 07 91 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 07 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 8e 69 5d 91 61 d2 9c 07 17 58 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_ARA_2147912177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.ARA!MTB"
        threat_id = "2147912177"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 0b 11 0f d3 18 5a 58 25 49 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b 16 95 1f 64 5e 1f 1e 59 d1 59 d1 53 00 11 0f 17 58 13 0f 11 0f 11 0d fe 04 13 10 11 10 2d c7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_SAL_2147913912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.SAL!MTB"
        threat_id = "2147913912"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 16 0c 2b 19 00 06 08 7e ?? ?? ?? 04 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 7e ?? ?? ?? 04 8e 69 fe 04 0d 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_KAG_2147919570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.KAG!MTB"
        threat_id = "2147919570"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 11 04 06 11 04 91 18 59 20 ff 00 00 00 5f d2 9c 11 04 17 58 13 04 11 04 06 8e 69}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_WPAA_2147921081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.WPAA!MTB"
        threat_id = "2147921081"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 08 16 07 16 1f 10 28 ?? 00 00 0a 08 16 07 1f 0f 1f 10 28 ?? 00 00 0a 06 07 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_KAU_2147921799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.KAU!MTB"
        threat_id = "2147921799"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 1f 28 62 09 1d 91 1f 21 61 6a 1f 20 62 09 18 91 20 ?? 00 00 00 61 6a 1f 38 62 09 16 91 1f 1f 61 6a 1e 62 09 1b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AYA_2147925308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AYA!MTB"
        threat_id = "2147925308"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$9f9f1272-892f-4127-ac93-6b385434b064" ascii //weight: 2
        $x_1_2 = "Users\\ADMIN\\source\\repos\\fuddd2\\fuddd2\\obj\\Release" ascii //weight: 1
        $x_1_3 = "/sc onlogon /rl highest" wide //weight: 1
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "GetRandomFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AYB_2147925310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AYB!MTB"
        threat_id = "2147925310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "miraculix.ru" wide //weight: 2
        $x_1_2 = "obj\\x86\\Release\\WindowsFormsApplication4.pdb" ascii //weight: 1
        $x_1_3 = "$4811c8a3-97ce-4ae8-8a76-751e18dbb8ab" ascii //weight: 1
        $x_1_4 = "ds_apdate.exe" wide //weight: 1
        $x_1_5 = "divsig_tasklist.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_ACDA_2147926044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.ACDA!MTB"
        threat_id = "2147926044"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 04 91 13 05 00 11 05 13 06 06 07 11 06 1f 0d 61 20 8f 00 00 00 61 20 e7 00 00 00 61 20 d3 00 00 00 61 1f 4f 61 20 d9 00 00 00 61 20 f0 00 00 00 61 20 d9 00 00 00 61 20 f6 00 00 00 61 20 9f 00 00 00 61 20 ee 00 00 00 61 1f 69 61 28 ?? 00 00 0a 9d 07 17 58 0b 00 11 04 17 58 13 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AXEA_2147927513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AXEA!MTB"
        threat_id = "2147927513"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b 69 38 6e 00 00 00 2b 31 72 ?? 00 00 70 2b 2d 2b 32 2b 37 72 ?? 00 00 70 2b 33 2b 38 2b 3d 6f ?? 00 00 0a 28 ?? 00 00 06 0b 07 16 07 8e 69 6f ?? 00 00 0a 0c 1e 2c cf de 2f 06 2b cc 28 ?? 00 00 0a 2b cc 6f ?? 00 00 0a 2b c7 06 2b c6 28 ?? 00 00 0a 2b c6 6f ?? 00 00 0a 2b c1 06 2b c0}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_ARAZ_2147928952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.ARAZ!MTB"
        threat_id = "2147928952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 09 11 06 58 28 ?? ?? ?? 2b 04 11 06 28 ?? ?? ?? 2b 2e 04 16 0c 2b 0b 11 06 17 58 13 06 11 06 07 32 dd}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_EAFZ_2147929550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.EAFZ!MTB"
        threat_id = "2147929550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 11 05 18 5b 07 11 05 18 6f 2e 00 00 0a 1f 10 28 2f 00 00 0a 9c 11 05 18 d6 13 05 11 05 11 04 31 de}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_AYC_2147929770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AYC!MTB"
        threat_id = "2147929770"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TelegramRAT" ascii //weight: 2
        $x_1_2 = "KEYLOGGER" wide //weight: 1
        $x_1_3 = "Sending screenshot..." wide //weight: 1
        $x_1_4 = "Is running on a VM:" wide //weight: 1
        $x_1_5 = "SELECT ProcessorId FROM Win32_Processor" wide //weight: 1
        $x_1_6 = "Select * From Win32_ComputerSystem" wide //weight: 1
        $x_1_7 = "CheckIfBeingAnalyzed" ascii //weight: 1
        $x_1_8 = "InstallAndAddToStartup" ascii //weight: 1
        $x_1_9 = "GetWifiProfilesAndPasswords" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_MBQ_2147933331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.MBQ!MTB"
        threat_id = "2147933331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {04 06 07 07 07 5f 60 91 06 07 91 61 06 07 91 61 d2}  //weight: 2, accuracy: High
        $x_2_2 = {06 07 03 07 04 58 91 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d e8}  //weight: 2, accuracy: High
        $x_1_3 = "Load" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Marsilia_SKAS_2147933871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.SKAS!MTB"
        threat_id = "2147933871"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 9a 13 04 7e ?? 00 00 04 11 04 18 28 ?? 00 00 06 20 ff 00 00 00 5f 13 05 08 09 7e ?? 00 00 04 11 05 28 ?? 00 00 06 9c 00 09 17 58 0d 09 07 8e 69 fe 04 13 07 11 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_BAA_2147935606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.BAA!MTB"
        threat_id = "2147935606"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {00 06 07 02 07 91 28 ?? 00 00 0a 03 6f ?? 00 00 0a 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d cd}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_SWA_2147936846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.SWA!MTB"
        threat_id = "2147936846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 7b 04 00 00 04 06 8f 03 00 00 02 28 1a 00 00 06 06 17 58 0a 06 6e 17 02 7b 05 00 00 04 1f 1f 5f 62 6a 32 db}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_SNI_2147937355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.SNI!MTB"
        threat_id = "2147937355"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 07 6f 11 00 00 0a 72 fe 5e 00 70 7e 03 00 00 04 28 05 00 00 06 6f 12 00 00 0a 26 07 6f 11 00 00 0a 72 20 5f 00 70 7e 03 00 00 04 28 05 00 00 06 6f 12 00 00 0a 26 07 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_SWB_2147940142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.SWB!MTB"
        threat_id = "2147940142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {12 00 12 01 28 07 00 00 06 02 06 07 28 08 00 00 06 51 28 09 00 00 06 0c 03 08 28 0a 00 00 06 51 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_SLDF_2147949348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.SLDF!MTB"
        threat_id = "2147949348"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8e 69 18 59 8d c3 00 00 01 0a 16 0b 18 0c 2b 2d 06 07 06 07 91 03 17 91 61 d2 9c 06 07 06 07 91 1f 18 61 d2 9c 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_ERYG_2147949720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.ERYG!MTB"
        threat_id = "2147949720"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0a 07 16 07 8e 69 ?? ?? ?? ?? ?? 0c 07 16 03 11 04 08 ?? ?? ?? ?? ?? 11 0b 07 16 08 ?? ?? ?? ?? ?? 09 08 58 0d 11 04 08 58 13 04 11 11 17 58 13 11 11 11 6a 11 0d 32 c7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marsilia_GTB_2147950281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.GTB!MTB"
        threat_id = "2147950281"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0b 16 0c 2b 1a 07 08 93 0d 06 09 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 08 17 d6 0c 08 07 8e 69 32 e0 06 6f 30}  //weight: 10, accuracy: Low
        $x_10_2 = {0a 16 0b 02 6f ?? 00 00 0a 0c 16 0d 2b 36 08 09 93 13 04 07 20 ?? ?? ?? ?? 2f 19 06 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 d6 0b 2b 0c 06 72 ?? 00 00 70 28 ?? 00 00 0a 0a 09 17 d6 0d 09 08 8e 69 32 c4}  //weight: 10, accuracy: Low
        $x_1_3 = "WindowsApp1.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Marsilia_AB_2147951414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marsilia.AB!MTB"
        threat_id = "2147951414"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 1a 00 20 2e 22 eb 4e 20 06 9d 10 15 61 20 01 00 00 00 63 20 f6 c4 88 f2 58 65 20 59 5b 79 df 61 61 fe 0e 1a 00 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

