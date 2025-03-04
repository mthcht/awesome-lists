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

