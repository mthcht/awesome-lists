rule Ransom_Win32_Mapo_2147748097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mapo!MSR"
        threat_id = "2147748097"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mapo"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KillProcess=sql|store|w3wp|inetinfo" ascii //weight: 1
        $x_1_2 = "EncryptedExt=mapo" ascii //weight: 1
        $x_1_3 = "MAPO-Readme.txt" ascii //weight: 1
        $x_1_4 = "STRICTLY FORBIDDEN TO USE NON-ORIGIN DECRYPTION TOOLS OR MODIFYING ENCRYPTED FILES" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

