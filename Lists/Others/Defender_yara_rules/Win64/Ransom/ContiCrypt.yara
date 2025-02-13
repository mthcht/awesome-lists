rule Ransom_Win64_ContiCrypt_PE_2147782093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ContiCrypt.PE!MTB"
        threat_id = "2147782093"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "conti_v3.dll" ascii //weight: 1
        $x_1_2 = {33 c9 8a 44 0d ?? 0f b6 c0 83 e8 ?? 6b c0 ?? 99 f7 fb 8d ?? ?? 99 f7 fb 88 54 0d ?? 41 83 f9 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_ContiCrypt_PG_2147782097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ContiCrypt.PG!MTB"
        threat_id = "2147782097"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 04 38 41 b8 ?? ?? ?? ?? 32 c3 80 c3 ?? 88 01 0f b6 c3 48 ff c1 84 db 41 0f 44 c0 ff c2 8a d8 8b c2 48 3b 44 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_ContiCrypt_PM_2147812311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ContiCrypt.PM!MTB"
        threat_id = "2147812311"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CONTI_README.txt" ascii //weight: 1
        $x_1_2 = ".CONTI" ascii //weight: 1
        $x_1_3 = "Your system is LOCKED." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_ContiCrypt_SL_2147834448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ContiCrypt.SL!MTB"
        threat_id = "2147834448"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hey guys, we've got more than 2 Tb of your data" ascii //weight: 1
        $x_1_2 = "deleted all your backups and crypted the whole domain" ascii //weight: 1
        $x_1_3 = "\\cryptor.pdb" ascii //weight: 1
        $x_1_4 = "qTox messenger" ascii //weight: 1
        $x_1_5 = "RSA2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

