rule Ransom_Win64_FileCryptor_C_2147750119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCryptor.C!MTB"
        threat_id = "2147750119"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jigsaw-ransomware" ascii //weight: 1
        $x_1_2 = "bitsadmin /transfer mydownloadjob /download" ascii //weight: 1
        $x_1_3 = "reg add HKEY_CURRENT_USER\\Control Panel\\Desktop /v Wallpaper" ascii //weight: 1
        $x_1_4 = "Decrypting your files now!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCryptor_X_2147771994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCryptor.X!MTB"
        threat_id = "2147771994"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\CurrentVersion\\Policies\\Explorer   /v NoRun" ascii //weight: 1
        $x_1_2 = "\\CurrentVersion\\Policies\\System   /v DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "Ransomware\\Fonix" ascii //weight: 1
        $x_1_4 = "End - GoodLuck" ascii //weight: 1
        $x_1_5 = "Encryption Completed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win64_FileCryptor_MAK_2147796007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCryptor.MAK!MTB"
        threat_id = "2147796007"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RANSOMWARE_KDF_INFO" ascii //weight: 1
        $x_1_2 = "expand 32-byte k" ascii //weight: 1
        $x_1_3 = "src/bin/ransomware.rs" ascii //weight: 1
        $x_1_4 = "panic payload" ascii //weight: 1
        $x_1_5 = "Local\\RustBacktraceMutex" ascii //weight: 1
        $x_1_6 = "Lazy instance has previously been poisoned" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCryptor_PR_2147815323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCryptor.PR!MTB"
        threat_id = "2147815323"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 c8 49 8b c2 80 e1 07 c0 e1 03 48 d3 e8 43 30 04 08 49 ff c0 49 83 f8 ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = "_encrypt_file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCryptor_AP_2147958793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCryptor.AP!AMTB"
        threat_id = "2147958793"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "**NEW VICTIM**" ascii //weight: 1
        $x_1_2 = "If the deadline is ignored, your files and stored credentials will be extracted and published on darknet marketplaces." ascii //weight: 1
        $x_1_3 = "\\\\VICTIM-PC\\ADMIN$\\svchost32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

