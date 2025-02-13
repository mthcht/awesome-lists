rule Ransom_Win32_Hackrypt_2147753186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hackrypt!MTB"
        threat_id = "2147753186"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hackrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Hack For Life" ascii //weight: 1
        $x_1_2 = "All Your Files Has Been Locked!" ascii //weight: 1
        $x_1_3 = "\\Unlock_All_Files.txt" ascii //weight: 1
        $x_1_4 = "FileUnlockFileEx\\Encrypt.exe" ascii //weight: 1
        $x_1_5 = {43 6f 6e 74 61 63 74 20 3a 20 [0-16] 40 67 6d 61 69 6c 2e 63 6f 6d 20 6f 72 20 68 74 74 70 73 3a 2f 2f 74 2e 6d 65 2f 66 69 6c 65 64 65 63 72 79 70 74 30 30 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

