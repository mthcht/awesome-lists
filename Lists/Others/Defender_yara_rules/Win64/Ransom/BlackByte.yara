rule Ransom_Win64_BlackByte_DKC_2147832570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackByte.DKC!MTB"
        threat_id = "2147832570"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackByte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 98 df 00 00 44 8b [0-6] 83 ee 20 ?? 8b f8 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {32 4c 24 04 41 32 ca 40 32 ce 41 32 cf 44 32 6c 24 08 88 4d 00 44 32 eb 44 32 ee 45 32 ef 44 88 6d 01 48 83 c5 04 48 83 6c 24 20 01 48 89 6c 24 18 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 04 1f 30 03 48 ff c3 48 83 e9 01 75 f1 48 83 ef 10 0f 29 ?? ?? 48 83 ee 01 75 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_BlackByte_FG_2147848231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackByte.FG!MTB"
        threat_id = "2147848231"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackByte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b c2 4d 8d 49 01 99 41 ff c2 f7 ff 48 63 c2 44 0f b6 04 18 45 30 41 ff 45 3b d3 7c e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_BlackByte_GB_2147930059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackByte.GB!MTB"
        threat_id = "2147930059"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackByte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.decFunc" ascii //weight: 1
        $x_1_2 = "main.Encrypt" ascii //weight: 1
        $x_1_3 = "main.Aes256Encr" ascii //weight: 1
        $x_1_4 = "main.DelShadows" ascii //weight: 1
        $x_1_5 = "main.Destroy" ascii //weight: 1
        $x_1_6 = "main.GrantAll" ascii //weight: 1
        $x_1_7 = "main.EnableLongPaths" ascii //weight: 1
        $x_1_8 = "main.GenDrives" ascii //weight: 1
        $x_1_9 = "main.CheckBusy" ascii //weight: 1
        $x_1_10 = "main.PreventSleep" ascii //weight: 1
        $x_1_11 = "main.ShowNote" ascii //weight: 1
        $x_1_12 = "main.Startproc" ascii //weight: 1
        $x_1_13 = "main.EnableLink" ascii //weight: 1
        $x_1_14 = "main.SetupKey" ascii //weight: 1
        $x_1_15 = "main.MountDrives" ascii //weight: 1
        $x_1_16 = "main.Kill" ascii //weight: 1
        $x_1_17 = "main.StopAllsvc" ascii //weight: 1
        $x_1_18 = "main.Encode" ascii //weight: 1
        $x_1_19 = "main.ClearRecycle" ascii //weight: 1
        $x_3_20 = "BlackByteGO/_cgo_gotypes.go" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_BlackByte_SZ_2147961064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackByte.SZ!MTB"
        threat_id = "2147961064"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackByte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Gentlemen, your network has been encrypted" ascii //weight: 1
        $x_1_2 = "modification of encrypted files will make recovery impossible" ascii //weight: 1
        $x_1_3 = "We have exfiltrated all your confidential and business data" ascii //weight: 1
        $x_1_4 = "Only we can decrypt your data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

