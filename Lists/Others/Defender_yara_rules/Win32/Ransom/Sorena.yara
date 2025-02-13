rule Ransom_Win32_Sorena_SK_2147757753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sorena.SK!MTB"
        threat_id = "2147757753"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sorena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All Your Files Has Been Locked!" ascii //weight: 1
        $x_1_2 = ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Hack For Security" ascii //weight: 1
        $x_1_3 = "C:/Users/ADMIN/go/scr/Encrypt/Encrypt.go" ascii //weight: 1
        $x_1_4 = "main.encrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sorena_PA_2147758698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sorena.PA!MTB"
        threat_id = "2147758698"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sorena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Go build ID: " ascii //weight: 1
        $x_2_2 = "All Your Files Has Been Locked!" ascii //weight: 2
        $x_2_3 = "\\How_to_Unlock_Files.txt" ascii //weight: 2
        $x_2_4 = "\\How_To_Decrypt_Files.txt" ascii //weight: 2
        $x_2_5 = "we can decrypt all your files after paying the ransom" ascii //weight: 2
        $x_2_6 = {43 6f 6e 74 61 63 74 20 3a 20 [0-21] 40 67 6d 61 69 6c 2e 63 6f 6d 20 6f 72 20 68 74 74 70 73 3a 2f 2f 74 2e 6d 65 2f 46 69 6c 65}  //weight: 2, accuracy: Low
        $x_2_7 = {43 3a 2f 55 73 65 72 73 2f [0-16] 2f 67 6f 2f 73 72 63 2f [0-16] 2f 45 6e 63 72 79 70 74 2e 67 6f}  //weight: 2, accuracy: Low
        $x_2_8 = "main.encrypt" ascii //weight: 2
        $x_2_9 = "FileUnlockFileEx\\Encrypt.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

