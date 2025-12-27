rule Ransom_Win64_Neveda_YBG_2147952632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Neveda.YBG!MTB"
        threat_id = "2147952632"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Neveda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 56 57 55 48 8d 35 05 fa fc ff 48 8d be 00 d0 fa ff 48 8d 87 c8 9c 07 00 ff 30 c7 00 db 62 f6 84 50 57 b8 72 21 08 00}  //weight: 1, accuracy: High
        $x_5_2 = {41 29 c3 41 29 c2 89 d0 66 c1 e8 05 8d 74 36 01 66 29 c2 66 41 89 10 eb 88 48 8b 4c 24 30 44 89 f8 41 ff c7 41 89 f5 40 88 34 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Neveda_YBH_2147952633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Neveda.YBH!MTB"
        threat_id = "2147952633"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Neveda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files were stolen and encrypted" ascii //weight: 1
        $x_1_2 = "Pay a ransom and save your reputation" ascii //weight: 1
        $x_1_3 = "post your critical data" ascii //weight: 1
        $x_1_4 = "to recover your files from backups" ascii //weight: 1
        $x_1_5 = "rename encrypted files" ascii //weight: 1
        $x_1_6 = "they contain viruses" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

