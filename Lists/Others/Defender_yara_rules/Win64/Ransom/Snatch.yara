rule Ransom_Win64_Snatch_PVA_2147756271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Snatch.PVA!MTB"
        threat_id = "2147756271"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Snatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID: \"CYMmKsMymnihvPTjf35k/" ascii //weight: 1
        $x_1_2 = "CFLMNPSZ" ascii //weight: 1
        $x_1_3 = "cryptacquirecontext" ascii //weight: 1
        $x_1_4 = "ImpersonateSelf" ascii //weight: 1
        $x_1_5 = "CryptGenRandom" ascii //weight: 1
        $x_1_6 = "NetUserGetInfo" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Snatch_PA_2147757434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Snatch.PA!MTB"
        threat_id = "2147757434"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Snatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Go build ID: \"2sK6gSW734NfBguuyn0H/FTFUloLoiAroVGT6Jb_E/F2jnF9VZC9JpBNTJ_ovO/8t_8v1ozd3K69RX_SxvO" ascii //weight: 10
        $x_10_2 = "at  fp= is  lr: of  on  pc= sp: sp=" ascii //weight: 10
        $x_1_3 = "CFLMNPSZ" ascii //weight: 1
        $x_1_4 = "encrypt" ascii //weight: 1
        $x_1_5 = "decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Snatch_A_2147762658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Snatch.A!MTB"
        threat_id = "2147762658"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Snatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 81 fb 00 08 00 00 0f 86 04 02 00 00 80 3d b6 13 31 00 01 75 11 89 f0 09 f8 a9 07 00 00 00 74 06 48 89 d9 f3 a4 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Snatch_X_2147763771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Snatch.X!MTB"
        threat_id = "2147763771"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Snatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "decrypt the files or bruteforce the key will be futile and lead to loss of time and precious data" ascii //weight: 1
        $x_1_2 = "Go build ID:" ascii //weight: 1
        $x_1_3 = "BEGIN RSA PUBLIC KEY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Snatch_PB_2147764813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Snatch.PB!MTB"
        threat_id = "2147764813"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Snatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Go build ID: \"iiuL9q5ZYrfmy4wOFyiM/KaD8D4zsl63EgnfKUFaC/2aszngurlKaNbWyZAmzg/OwXzx0IqQiqnwkVyihGr" ascii //weight: 10
        $x_1_2 = "at  fp= is  lr: of  on  pc= sp: sp=" ascii //weight: 1
        $x_1_3 = "main.ransomNote" ascii //weight: 1
        $x_1_4 = "http.http2ClientConn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Snatch_MA_2147893390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Snatch.MA!MTB"
        threat_id = "2147893390"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Snatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 6b c9 03 48 8b 15 ?? ?? ?? ?? 89 84 0a f4 00 00 00 48 63 44 24 48 48 8b 8c 24 c8 00 00 00 48 8b 89 80 00 00 00 8b 04 81 89 44 24 3c 8b 44 24 3c 0f af 05 ?? ?? ?? ?? 89 44 24 3c 8b 44 24 3c c1 e8 10 48 8b 8c 24 c8 00 00 00 48 63 49 50 48 8b 15 ?? ?? ?? ?? 48 8b 92 98 00 00 00 88 04 0a}  //weight: 5, accuracy: Low
        $x_5_2 = {c1 e8 08 48 8b 0d ?? ?? ?? ?? 48 63 49 50 48 8b 15 ?? ?? ?? ?? 48 8b 92 98 00 00 00 88 04 0a 48 8b 05 ?? ?? ?? ?? 8b 40 50 ff c0 48 8b 0d ?? ?? ?? ?? 89 41 50 48 8b 05 ?? ?? ?? ?? 8b 40 2c 83 f0 0a 48 8b 0d ?? ?? ?? ?? 8b 89 b0 00 00 00 0b c8 8b c1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Snatch_PC_2147917344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Snatch.PC!MTB"
        threat_id = "2147917344"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Snatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".enc202407" ascii //weight: 1
        $x_1_2 = "ReadMe.txt" ascii //weight: 1
        $x_1_3 = "main.encryptFile" ascii //weight: 1
        $x_4_4 = "All your data has been encrypted by me" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

