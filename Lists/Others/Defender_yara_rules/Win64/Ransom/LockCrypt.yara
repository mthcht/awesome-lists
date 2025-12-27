rule Ransom_Win64_LockCrypt_PB_2147793917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockCrypt.PB!MTB"
        threat_id = "2147793917"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 c0 88 44 24 ?? 0f b6 44 24 ?? 0f 1f 40 00 0f be 44 14 ?? 8b 4c 24 ?? ?? ca 33 c8 88 4c 14 ?? 48 ff c2 48 83 fa 0d 72}  //weight: 3, accuracy: Low
        $x_3_2 = {33 c0 88 44 24 ?? 0f b6 44 24 ?? 48 8b c6 66 90 0f be 4c 04 ?? 8b 54 24 ?? ?? d0 33 d1 88 54 04 ?? 48 ff c0 48 83 f8 0d 72}  //weight: 3, accuracy: Low
        $x_1_3 = ".atomsilo" ascii //weight: 1
        $x_1_4 = "winsta0\\default" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockCrypt_PC_2147797015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockCrypt.PC!MTB"
        threat_id = "2147797015"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GENBOTID" ascii //weight: 1
        $x_1_2 = "README_FOR_DECRYPT.txt" ascii //weight: 1
        $x_1_3 = "/Bnyar8RsK04ug" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockCrypt_PA_2147946499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockCrypt.PA!MTB"
        threat_id = "2147946499"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "READ_TO_DECRYPT.txt" ascii //weight: 1
        $x_1_2 = "/upload_stolen.php" ascii //weight: 1
        $x_2_3 = "YOUR FILES HAVE BEEN ENCRYPTED!" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

