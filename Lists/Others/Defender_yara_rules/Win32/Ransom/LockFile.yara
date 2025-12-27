rule Ransom_Win32_LockFile_MK_2147789394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockFile.MK!MTB"
        threat_id = "2147789394"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncodingParameters" ascii //weight: 1
        $x_1_2 = "LOCKFILE" ascii //weight: 1
        $x_1_3 = "<computername>%s</computername>" ascii //weight: 1
        $x_1_4 = "<blocknum>%d</blocknum>" ascii //weight: 1
        $x_1_5 = "winsta0\\default" ascii //weight: 1
        $x_1_6 = "cmd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockFile_ALK_2147946752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockFile.ALK!MTB"
        threat_id = "2147946752"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f bd f7 0f bd d1 83 f6 1f 83 f2 1f 83 ce 20 80 7c 24 10 00 0f 44 d6 0f bd f3 0f bd c8 83 f6 1f 83 f1 1f 83 ce 20 85 c0 0f 45 f1 83 ce 40 0b 7c 24 08 0f 45 f2 6a 7b 5f 29 f7}  //weight: 3, accuracy: High
        $x_2_2 = "Your infrastructure DeadLocked" ascii //weight: 2
        $x_1_3 = "All Files stolen and encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockFile_FGG_2147948024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockFile.FGG!MTB"
        threat_id = "2147948024"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {32 04 3e 32 85 ?? ?? ?? ?? 8b 4d e4 88 04 31 8b 45 c0 8b 7d d4 89 45 e4 8a 04 30 46 88 85 ?? ?? ?? ?? 8b 45 d8 2b c7 3b f0 72}  //weight: 5, accuracy: Low
        $x_2_2 = "NotGetUp\\encrypt\\Release\\encrypt.pdb" ascii //weight: 2
        $x_1_3 = ".locked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockFile_AP_2147958235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockFile.AP!AMTB"
        threat_id = "2147958235"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Files are encrypted and injected into image" ascii //weight: 1
        $x_1_2 = "A ransom note with the victim ID is placed in each targeted directory" ascii //weight: 1
        $x_1_3 = "Before encryption started the single ransomnote is created in the root directory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

