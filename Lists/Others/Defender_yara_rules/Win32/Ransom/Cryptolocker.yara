rule Ransom_Win32_Cryptolocker_PDP_2147778404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PDP!MTB"
        threat_id = "2147778404"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WanaCrypt0r" ascii //weight: 1
        $x_1_2 = ".wnry" ascii //weight: 1
        $x_1_3 = "WANACRY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryptolocker_PDP_2147778404_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PDP!MTB"
        threat_id = "2147778404"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your All Files Encrypted" ascii //weight: 1
        $x_1_2 = "ScorpionEncryption" ascii //weight: 1
        $x_1_3 = "Read-Me-Now" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryptolocker_PDP_2147778404_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PDP!MTB"
        threat_id = "2147778404"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILES ENCRYPTED" ascii //weight: 1
        $x_1_2 = "TouchMeNot" ascii //weight: 1
        $x_1_3 = "RECYCLER\\__empty" ascii //weight: 1
        $x_1_4 = "System Volume Information\\__empty" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryptolocker_PDP_2147778404_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PDP!MTB"
        threat_id = "2147778404"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe delete shadows /all /Quiet" ascii //weight: 1
        $x_1_2 = "ENCRYPTED_EXTENTION" ascii //weight: 1
        $x_1_3 = "ENCRYPT_KEY" ascii //weight: 1
        $x_1_4 = "DECRYPT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryptolocker_PDP_2147778404_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PDP!MTB"
        threat_id = "2147778404"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c vssadmin.exe delete shadows /quiet /all" ascii //weight: 1
        $x_1_2 = "BEGIN PUBLIC KEY" ascii //weight: 1
        $x_1_3 = "BEGIN RSA PRIVATE KEY" ascii //weight: 1
        $x_1_4 = "GetLogicalDrives" ascii //weight: 1
        $x_1_5 = "FindFirstFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryptolocker_PDP_2147778404_5
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PDP!MTB"
        threat_id = "2147778404"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DisableTaskMgr" ascii //weight: 1
        $x_1_2 = "DisableRegistryTools" ascii //weight: 1
        $x_1_3 = "Search File Using Extension" ascii //weight: 1
        $x_1_4 = "GetTempPathA" ascii //weight: 1
        $x_1_5 = "FindNextFileA" ascii //weight: 1
        $x_1_6 = "SHEmptyRecycleBinA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryptolocker_PDR_2147778644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PDR!MTB"
        threat_id = "2147778644"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "babyDontHeartMe" ascii //weight: 1
        $x_1_2 = "we can decrypt one file" ascii //weight: 1
        $x_1_3 = "@tutanota.com" ascii //weight: 1
        $x_1_4 = "Tor Browser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryptolocker_PDR_2147778644_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PDR!MTB"
        threat_id = "2147778644"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fuckyou" ascii //weight: 1
        $x_1_2 = "Decrypt-me" ascii //weight: 1
        $x_1_3 = "recoverfiles" ascii //weight: 1
        $x_1_4 = "recoveryenabled no" ascii //weight: 1
        $x_1_5 = "DisableTaskmgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryptolocker_PDR_2147778644_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PDR!MTB"
        threat_id = "2147778644"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files were encrypted" ascii //weight: 1
        $x_1_2 = "TouchMeNot" ascii //weight: 1
        $x_1_3 = ".CrYpTeD" ascii //weight: 1
        $x_1_4 = "decrypted successfully" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryptolocker_PDR_2147778644_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PDR!MTB"
        threat_id = "2147778644"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files were encrypted" ascii //weight: 1
        $x_1_2 = "AES-256 MILLITARY" ascii //weight: 1
        $x_1_3 = "RESTORE GET BACK YOUR FILES" ascii //weight: 1
        $x_1_4 = "@protonmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryptolocker_PDR_2147778644_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PDR!MTB"
        threat_id = "2147778644"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "BEGIN PUBLIC KEY" ascii //weight: 1
        $x_1_3 = "BEGIN RSA PRIVATE KEY" ascii //weight: 1
        $x_1_4 = "BASE64ENCRYPTED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryptolocker_PAC_2147786677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PAC!MTB"
        threat_id = "2147786677"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Content-Type: application/x-www-form-urlencoded" wide //weight: 1
        $x_1_2 = "cmd.exe /C ping 3.4.2.1 -n 4" wide //weight: 1
        $x_1_3 = " & rmdir /Q /S \"" wide //weight: 1
        $x_1_4 = "-name=%ls&delete=" ascii //weight: 1
        $x_1_5 = "phpinfo.php" wide //weight: 1
        $x_1_6 = "\\winmsism" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryptolocker_PAJ_2147795382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PAJ!MTB"
        threat_id = "2147795382"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$FileStreamWriter.Write([System.BitConverter]::GetBytes($Crypto.IV.Length)" ascii //weight: 1
        $x_1_2 = "powershell -ExecutionPolicy ByPass -File" ascii //weight: 1
        $x_1_3 = "Your personal files have been encrypted" ascii //weight: 1
        $x_1_4 = "-Suffix '.locked' -RemoveSource" ascii //weight: 1
        $x_1_5 = "Readme_now.txt" ascii //weight: 1
        $x_1_6 = "cry.ps1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryptolocker_PAK_2147798131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PAK!MTB"
        threat_id = "2147798131"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C kill.bat" ascii //weight: 1
        $x_1_2 = "i will recover your files!" ascii //weight: 1
        $x_1_3 = "d2VsbCB0aGlzIHN1Y2tzLCBoYSE=" ascii //weight: 1
        $x_1_4 = "bW9uZXksIG1vbmV5LCBtb25leSE=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryptolocker_PAL_2147814158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PAL!MTB"
        threat_id = "2147814158"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fastInfector" ascii //weight: 1
        $x_1_2 = "\\Antivirus.bat" ascii //weight: 1
        $x_1_3 = "taskkill /IM mspub.exe /F" ascii //weight: 1
        $x_1_4 = "net stop BMR Boot Service /y" ascii //weight: 1
        $x_1_5 = "bcdedit /set {default} recoveryenabled No" ascii //weight: 1
        $x_1_6 = "vssadmin Delete Shadows /all /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Cryptolocker_PAM_2147814504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.PAM!MTB"
        threat_id = "2147814504"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Good Luck!" ascii //weight: 1
        $x_1_2 = "Lockit@std" ascii //weight: 1
        $x_1_3 = "CHECK_YOUR_FILES_NOW_LOLOL" ascii //weight: 1
        $x_1_4 = "You don't have anything more to do!" ascii //weight: 1
        $x_1_5 = "Hello sir, your files was been ripped off" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cryptolocker_MKZ_2147926120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptolocker.MKZ!MTB"
        threat_id = "2147926120"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c6 03 82 80 f4 00 00 8b 54 24 14 21 04 8a 8b 0b 83 eb 04 a1 ?? ?? ?? ?? 46 45 c7 04 88 23 10 00 00 a1 ?? ?? ?? ?? 0f b7 c0 3b 34 87 7e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

