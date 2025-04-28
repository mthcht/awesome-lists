rule Ransom_Win32_Satan_S_2147749843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Satan.S!MSR"
        threat_id = "2147749843"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Satan"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\5ss5c" ascii //weight: 1
        $x_1_2 = "5ss5c" ascii //weight: 1
        $x_1_3 = "5ss5c_token" ascii //weight: 1
        $x_1_4 = "5ss5c_CRYPT" ascii //weight: 1
        $x_1_5 = "5ss5c@mail.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Satan_AJY_2147773010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Satan.AJY!MSR"
        threat_id = "2147773010"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Satan"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Some files have been encrypted" ascii //weight: 1
        $x_1_2 = "Email:dbger@protonmail.com" ascii //weight: 1
        $x_1_3 = "C:\\_How_to_decrypt_files.txt" ascii //weight: 1
        $x_1_4 = "If you exceed the payment time, your data will be open to the public download" ascii //weight: 1
        $x_1_5 = "DBGERAPP" ascii //weight: 1
        $x_1_6 = "C:\\Program Files\\WebMoney\\[dbger@protonmail.com]__empty.dbger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Satan_SIB_2147805926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Satan.SIB!MTB"
        threat_id = "2147805926"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Satan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 80 f9 ff 75 ?? 80 78 01 25 74 ?? 80 f9 e9 75 ?? 33 c0 40 eb ?? 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {33 ff 8b da 66 3b 04 f5 ?? ?? ?? ?? 73 ?? 8b 04 f5 ?? ?? ?? ?? 0f b7 d7 66 0f be 0c 10 b8 ?? ?? ?? ?? 66 33 cf 66 23 c8 0f b6 04 f5 ?? ?? ?? ?? 66 33 c8 47 66 89 0c 53 66 3b 3c f5 00 72 ?? 0f b7 04 f5 00 33 c9 5f 5e 66 89 0c 43}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c2 33 ed 89 44 24 ?? 89 4c 24 ?? 8a 9f ?? ?? ?? ?? 8a bf ?? ?? ?? ?? 85 c0 74 ?? 56 fe c3 0f b6 f3 8a 14 3e 02 fa 0f b6 cf 8a 04 39 88 04 3e 88 14 39 0f b6 0c 3e 0f b6 c2 03 c8 81 e1 ff 00 00 00 8a 04 39 8b 4c 24 ?? 30 04 29 45 3b 6c 24 ?? 72 ?? 5e 88 9f 02 88 bf}  //weight: 1, accuracy: Low
        $x_1_4 = {33 f6 8b da 8b e9 39 35 ?? ?? ?? ?? 75 ?? 57 8b fe b9 ?? ?? ?? ?? 6a 08 8b c7 5a a8 01 74 ?? d1 e8 35 ?? ?? ?? ?? eb ?? d1 e8 4a 75 ?? 89 01 47 83 c1 04 81 ff ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c9 ff 85 db 74 ?? 0f b6 04 2e 33 c1 c1 e9 ?? 25 ?? ?? ?? ?? 33 0c 85 c0 83 41 00 46 3b f3 72 ?? [0-5] 8b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Satan_AYA_2147940214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Satan.AYA!MTB"
        threat_id = "2147940214"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Satan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\source\\ransomware\\ransomware.cpp" ascii //weight: 2
        $x_1_2 = "Infection thread started" wide //weight: 1
        $x_1_3 = "This is not the first time the ransomware is running." wide //weight: 1
        $x_1_4 = "Encrypting the files in the profile directory ended." wide //weight: 1
        $x_1_5 = "Failed to allocate memory for the ransom note." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

