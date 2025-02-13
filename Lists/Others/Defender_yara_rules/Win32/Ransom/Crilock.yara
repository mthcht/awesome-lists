rule Ransom_Win32_Crilock_A_2147683128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crilock.A"
        threat_id = "2147683128"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crilock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 00 00 00 00 5b 8d 43 36 bf ?? ?? ?? ?? b9 ?? ?? ?? ?? 89 fa 31 db 89 ce 83 e6 03 75 10}  //weight: 5, accuracy: Low
        $x_1_2 = "\\fs20 Bitcoin is a cryptocurrency where" ascii //weight: 1
        $x_1_3 = "Getting started with Bitcoin}}}\\cf1\\ulnone\\b0\\f0\\fs20\\par" ascii //weight: 1
        $x_1_4 = "nobody and never will be able\\b0  to restore files...\\par" ascii //weight: 1
        $x_1_5 = "%AMOUNT_USD% USD\\b0  / \\b %AMOUNT_EUR% EUR\\b0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Crilock_A_2147683128_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crilock.A"
        threat_id = "2147683128"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crilock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 41 4d 4f 55 4e 54 5f 42 54 43 25 00 00 00 00 25 42 49 54 43 4f 49 4e 5f 41 44 44 52 45 53 53 25 00}  //weight: 1, accuracy: High
        $x_1_2 = {76 65 72 73 69 6f 6e 3d 25 75 26 69 64 3d 25 75 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 00 6f 00 6e 00 65 00 79 00 70 00 61 00 6b 00 00 00 70 00 61 00 79 00 73 00 61 00 66 00 65 00 63 00 61 00 72 00 64 00 00 00 75 00 6b 00 61 00 73 00 68 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {54 00 69 00 6d 00 65 00 20 00 6c 00 65 00 66 00 74 00 00 00 25 00 75 00 20 00 3a 00 20 00 25 00 30 00 32 00 75 00 20 00 3a 00 20 00 25 00 30 00 32 00 75 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 00 72 00 79 00 70 00 74 00 6f 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 25 00 68 00 73 00 2f 00 31 00 30 00 30 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "Your important files \\b encryption\\b0  produced on this computer: photos, videos, documents, etc." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Crilock_B_2147683592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crilock.B"
        threat_id = "2147683592"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crilock"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 50 02 8d 48 04 83 fa 72 75}  //weight: 1, accuracy: High
        $x_1_2 = {68 67 01 00 00 68 e5 01 00 00 68 a5 00 00 00 68 2f 01 00 00 51 8b 8e 20 01 00 00 e8 ?? ?? ?? ?? 8b 96 20 01 00 00 85 d2 74 77}  //weight: 1, accuracy: Low
        $x_1_3 = {02 c1 32 04 (32|16) 88 02 8d 43 01}  //weight: 1, accuracy: Low
        $x_1_4 = {81 7f 08 52 53 41 31 75 ?? 8d 43 14 3b f0 75}  //weight: 1, accuracy: Low
        $x_1_5 = {85 f6 b8 61 00 00 00 0f 44 c3 66 0f be c8 0f b6 c2 99 f7 7d 08 66 03 ca 66 89 0f 83 c7 02 46 83 fe 14}  //weight: 1, accuracy: High
        $x_1_6 = {8a 04 0f 8d 49 01 32 04 32 88 41 ff 8d 42 01 33 d2 f7 75 18 4b 75 e9}  //weight: 1, accuracy: High
        $x_1_7 = {75 55 c7 45 f4 00 a4 00 00 b8 00 00 00 01 eb 09 c7 45 f4 10 66 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

