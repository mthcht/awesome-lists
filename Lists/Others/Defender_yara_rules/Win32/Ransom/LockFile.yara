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

