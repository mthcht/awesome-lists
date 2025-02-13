rule Ransom_Win32_FileCrypter_MK_2147762105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCrypter.MK!MTB"
        threat_id = "2147762105"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encrypted by BlackRabbit" ascii //weight: 1
        $x_1_2 = "{ENCRYPTENDED}" ascii //weight: 1
        $x_1_3 = "{ENCRYPTSTART}" ascii //weight: 1
        $x_1_4 = "how_to_decrypt.hta" ascii //weight: 1
        $x_1_5 = "config.txt" ascii //weight: 1
        $x_1_6 = "hta.txt" ascii //weight: 1
        $x_1_7 = "/c \"ping 0.0.0.0&del \"" ascii //weight: 1
        $x_1_8 = "END ENCRYPT ONLY EXTENATIONS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCrypter_MK_2147762105_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCrypter.MK!MTB"
        threat_id = "2147762105"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Files have been encrypted!And Your computer has been limited!" ascii //weight: 5
        $x_1_2 = "Reference Number : CT -" ascii //weight: 1
        $x_5_3 = "send $40 to our bitcoin wallet" ascii //weight: 5
        $x_1_4 = "flag in base64:" ascii //weight: 1
        $x_5_5 = "There's malware everywhere" ascii //weight: 5
        $x_1_6 = "AttentionVictim" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCrypter_2147762276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCrypter!MTB"
        threat_id = "2147762276"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "txt|vbs|jsp|php|wav|swf|wmv|mpg|mpeg|avi|mov|mkv|flv|svg|psd|gif|bmp|iso|bck" ascii //weight: 1
        $x_1_2 = "download/Decryptor.exe" ascii //weight: 1
        $x_1_3 = "download/Backdoor.exe" ascii //weight: 1
        $x_1_4 = "RANSOMWARE_SEC" ascii //weight: 1
        $x_1_5 = "PSNSOMWARE - A PSN RANSOMWARE - Can't execute !" ascii //weight: 1
        $x_1_6 = "\"decryption-key\":" ascii //weight: 1
        $x_1_7 = "\\AppData\\psnomware" ascii //weight: 1
        $x_1_8 = ".psnomware" ascii //weight: 1
        $x_1_9 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\backdoor.exe" ascii //weight: 1
        $x_1_10 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\readme.html" ascii //weight: 1
        $x_1_11 = "<title>PSNOMWARE ransomware</title>" ascii //weight: 1
        $x_1_12 = "\\Desktop\\Decryptor.exe" ascii //weight: 1
        $x_1_13 = "\\Desktop\\README.HTML" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Ransom_Win32_FileCrypter_MB_2147763484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCrypter.MB!MTB"
        threat_id = "2147763484"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "schtasks /Create /SC MINUTE /TN" ascii //weight: 2
        $x_2_2 = "wmic SHADOWCOPY DELETE" ascii //weight: 2
        $x_2_3 = "wbadmin DELETE SYSTEMSTATEBACKUP" ascii //weight: 2
        $x_2_4 = "bcdedit.exe / set{ default } bootstatuspolicy ignoreallfailures" ascii //weight: 2
        $x_2_5 = "bcdedit.exe / set{ default } recoveryenabled No" ascii //weight: 2
        $x_2_6 = "vssadmin.exe Delete Shadows / All / Quiet" ascii //weight: 2
        $x_1_7 = "HOW TO RESTORE FILES.TXT" ascii //weight: 1
        $x_1_8 = "All your files were encrypted" ascii //weight: 1
        $x_1_9 = ".mouse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCrypter_M_2147766821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCrypter.M!MTB"
        threat_id = "2147766821"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "at  fp= is  lr: of  on  pc= sp: sp=" ascii //weight: 1
        $x_1_3 = "unreachableuserenv.dll" ascii //weight: 1
        $x_1_4 = "FP_NO_HOST_CHECK" ascii //weight: 1
        $x_1_5 = "lockfile" ascii //weight: 1
        $x_1_6 = "UnlockFile" ascii //weight: 1
        $x_1_7 = ".SNPDRGN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

