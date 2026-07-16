rule Ransom_Win32_LockCrypt_A_2147721822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockCrypt.A!bit"
        threat_id = "2147721822"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockCrypt"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d_dukens@aol.com" ascii //weight: 1
        $x_1_2 = "All your files have beenencrypted!" ascii //weight: 1
        $x_1_3 = "vssadmin delete shadows /all" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockCrypt_PAA_2147762403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockCrypt.PAA!MTB"
        threat_id = "2147762403"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!RECOVER.txt" ascii //weight: 1
        $x_1_2 = "svchost2" ascii //weight: 1
        $x_1_3 = "beijing520@" ascii //weight: 1
        $x_1_4 = "ALL YOUR DATA WAS ENCRYPTED" ascii //weight: 1
        $x_1_5 = "__lock_XXX__" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockCrypt_G_2147765678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockCrypt.G!MSR"
        threat_id = "2147765678"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockCrypt"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attention!!! Your files are encrypted !!!" ascii //weight: 1
        $x_1_2 = "To recover files, follow the prompts in the text file \"Readme\"" ascii //weight: 1
        $x_1_3 = "vssadmin delete shadows /all" ascii //weight: 1
        $x_1_4 = "MPGoodStatus" ascii //weight: 1
        $x_1_5 = "download key ok" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockCrypt_MAK_2147808365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockCrypt.MAK!MTB"
        threat_id = "2147808365"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "download key ok" ascii //weight: 1
        $x_1_2 = "Attention!!! Your files are encrypted !!!" ascii //weight: 1
        $x_1_3 = "To recover files, follow the prompts in the text file" ascii //weight: 1
        $x_1_4 = "vssadmin delete shadows /all" ascii //weight: 1
        $x_1_5 = "Do not rename encrypted files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_LockCrypt_PD_2147809019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockCrypt.PD!MTB"
        threat_id = "2147809019"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Bnyar8RsK04ug/" ascii //weight: 1
        $x_1_2 = "/BnpOnspQwtjCA/register" ascii //weight: 1
        $x_1_3 = "173.232.146.118" ascii //weight: 1
        $x_1_4 = "README_FOR_" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockCrypt_ARR_2147973696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockCrypt.ARR!MTB"
        threat_id = "2147973696"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 c1 02 c1 34 ?? 02 c1 32 c1 02 c1 32 c1 2c ?? 32 c1 02 c1}  //weight: 10, accuracy: Low
        $x_5_2 = {8b 0a 33 c8 23 cb 33 c8 8b c1 d1 e9 83 e0 01 8b 04 85 ?? ?? ?? ?? 33 82 70 ?? ?? ?? 33 c1 89 07 8b fa 8b 02}  //weight: 5, accuracy: Low
        $x_4_3 = "To restore files write to the mail: lokeradmin@cock.li" ascii //weight: 4
        $x_3_4 = "If we dont respond within 24 hours - write to the mail: adminsysloker@airmail.cc" ascii //weight: 3
        $x_1_5 = "In subject: {KEY11111}" ascii //weight: 1
        $x_2_6 = "If you dont write immediately - the price will be higher." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

