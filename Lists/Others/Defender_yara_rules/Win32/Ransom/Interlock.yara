rule Ransom_Win32_Interlock_DA_2147965137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Interlock.DA!MTB"
        threat_id = "2147965137"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Interlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encrypt specified directory" ascii //weight: 1
        $x_1_2 = "Encrypt specified file" ascii //weight: 1
        $x_1_3 = "Delete Interlock encryptor" ascii //weight: 1
        $x_1_4 = "Execute as scheduled task" ascii //weight: 1
        $x_1_5 = "Release files using the Restart Manager" ascii //weight: 1
        $x_1_6 = "Stores encrypted session keys" ascii //weight: 1
        $x_1_7 = "!_KEYS_FOR_DECRYPT_!" ascii //weight: 1
        $x_1_8 = "inside the encrypted files" ascii //weight: 1
        $x_1_9 = "FIRST_READ_ME.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

