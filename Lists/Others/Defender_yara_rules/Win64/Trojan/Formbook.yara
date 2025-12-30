rule Trojan_Win64_Formbook_DG_2147775943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Formbook.DG!MTB"
        threat_id = "2147775943"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "outCompiled.exe" ascii //weight: 1
        $x_1_2 = "BlockCopy" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TripleDESCryptoServiceProvider" ascii //weight: 1
        $x_1_5 = "System.CodeDom.Compiler" ascii //weight: 1
        $x_1_6 = "Create__Instance__" ascii //weight: 1
        $x_1_7 = ".resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Formbook_RPY_2147901220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Formbook.RPY!MTB"
        threat_id = "2147901220"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 8b 4e 28 44 89 4d ac c7 44 24 20 40 00 00 00 49 8b cd 48 89 4d 80 48 8b d7 48 89 95 78 ff ff ff 44 89 45 8c 41 b9 00 30 00 00 44 89 4d 88 48 8d 8d 50 ff ff ff e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Formbook_RR_2147960191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Formbook.RR!MTB"
        threat_id = "2147960191"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 b9 79 37 9e 45 8b c8 41 c1 e1 04 44 03 4e 10 45 8d 1c 00 45 33 cb 45 8b d8 41 c1 eb 05 44 03 5e 14 45 33 cb 41 03 d1 44 8b ca 41 c1 e1 04 44 03 4e 18 44 8d 1c 02 45 33 cb 44 8b da 41 c1 eb 05 44 03 5e 1c 45 33 cb 45 03 c1 41 ff ca 75}  //weight: 1, accuracy: High
        $x_1_2 = {4d 33 c2 4c 89 02 48 8d 56 18 4c 8b 0a 4c 03 4e 20 4c 89 0a 49 8b d1 48 c1 e2 11 49 c1 e9 2f 49 0b d1 48 89 56 18 48 8d 56 18 4d 8b c8 4c 33 0a 4c 89 0a 48 8d 56 20 4c 03 12 4c 89 12 49 8b d2 48 c1 e2 17 49 c1 ea 29 49 0b d2 48 89 56 20 48 8d 56 20 4c 33 0a 4c 89 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

