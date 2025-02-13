rule Ransom_Win32_DarkSide_G_2147762180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DarkSide.G!MSR"
        threat_id = "2147762180"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkSide"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "----------- [ Welcome to Dark ] ------------->" ascii //weight: 1
        $x_1_2 = "First of all we have uploaded more then 100 GB data." ascii //weight: 1
        $x_1_3 = "After publication, your data will be available for at least 6 months on our tor cdn servers." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_DarkSide_2147770086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DarkSide!MSR"
        threat_id = "2147770086"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkSide"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Elevation:Administrator" ascii //weight: 1
        $x_1_2 = "Welcome to DarkSide" ascii //weight: 1
        $x_1_3 = "securebestapp20.com" wide //weight: 1
        $x_1_4 = "VMProtect" ascii //weight: 1
        $x_1_5 = "All of your files are encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DarkSide_DA_2147773523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DarkSide.DA!MTB"
        threat_id = "2147773523"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkSide"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your computers and servers are encrypted" ascii //weight: 1
        $x_1_2 = "Welcome to DarkSide" ascii //weight: 1
        $x_1_3 = "torproject.org" ascii //weight: 1
        $x_1_4 = "DO NOT MODIFY or try to RECOVER any files yourself" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DarkSide_DA_2147780888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DarkSide.DA"
        threat_id = "2147780888"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkSide"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 54 0e 0c 89 44 0e 08 89 5c 0e 04 89 3c 0e 81 ea 10 10 10 10 2d 10 10 10 10 81 eb 10 10 10 10 81 ef 10 10 10 10}  //weight: 1, accuracy: High
        $x_1_2 = {02 14 1e 02 d0 8a ?? ?? ?? ?? 00 43 88 ?? ?? ?? ?? 00 88 ?? ?? ?? ?? 00 3b df 73 06 fe c1 75 da eb 06 33 db fe c1 75 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DarkSide_MFP_2147787053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DarkSide.MFP!MTB"
        threat_id = "2147787053"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkSide"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 54 0e 0c 89 44 0e 08 89 5c 0e 04 89 3c 0e 81 ea 10 10 10 10 2d 10 10 10 10 81 eb 10 10 10 10 81 ef 10 10 10 10 83 e9 10 79 d5}  //weight: 1, accuracy: High
        $x_1_2 = {88 64 1e fe 02 c2 8b 7d 0c c1 eb 02 8d 14 5b 2b d0 52 89 5d fc 8b 0e 0f b6 d1 0f b6 dd 57 8d bd fc fe ff ff 8a 04 3a 8a 24 3b c1 e9 10 83 c6 04 0f b6 d1 0f b6 cd 8a 1c 3a 8a 3c 39 5f 8a d4 8a f3 c0 e0 02 c0 eb 02 c0 e6 06 c0 e4 04 c0 ea 04 0a fe 0a c2 0a e3 88 07 88 7f 02 88 67 01 ff 4d fc 8d 7f 03 75 af}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DarkSide_ADA_2147850645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DarkSide.ADA!MTB"
        threat_id = "2147850645"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkSide"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 9a bf 0b 41 00 8a 82 bf 0b 41 00 8a ab be 0b 41 00 88 83 be 0b 41 00 88 aa bf 0b 41 00 02 c5 47 8a 80 be 0b 41 00 fe c2 30 07 fe c9 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DarkSide_ADK_2147851028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DarkSide.ADK!MTB"
        threat_id = "2147851028"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkSide"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 73 52 08 02 5b 5b bb 2d 8c 15 30 06 3a 4b 36 34 a3 aa 06 ad d1 1a b6 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

