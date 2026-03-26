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

rule Ransom_Win64_ContiCrypt_PAHU_2147965035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ContiCrypt.PAHU!MTB"
        threat_id = "2147965035"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SELECT * FROM Win32_ShadowCopy" wide //weight: 2
        $x_1_2 = "cmd.exe /c vssadmin delete shadows /all /quiet" wide //weight: 1
        $x_2_3 = "cmd.exe /c wbadmin DELETE BACKUP" wide //weight: 2
        $x_1_4 = "encrypt" wide //weight: 1
        $x_2_5 = "CONTI_LOG.txt" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_ContiCrypt_PAHR_2147965698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ContiCrypt.PAHR!MTB"
        threat_id = "2147965698"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Crittografia completata" ascii //weight: 2
        $x_2_2 = "Inizio scansione e criptazione" ascii //weight: 2
        $x_1_3 = "creazione thread shellcode" ascii //weight: 1
        $x_1_4 = "Errore nell'aggiustare i privilegi" ascii //weight: 1
        $x_1_5 = "Errore durante la creazione dello snapshot di processo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

