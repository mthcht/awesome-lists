rule Ransom_Win32_Revil_SD_2147763044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Revil.SD!MTB"
        threat_id = "2147763044"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Revil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kremez and hszrd fuckoff.txt" ascii //weight: 1
        $x_1_2 = "polish prostitute" ascii //weight: 1
        $x_1_3 = "Error_double_run" ascii //weight: 1
        $x_1_4 = "ServicesActive" ascii //weight: 1
        $x_1_5 = "expand 32-byte kexpand 16-byte k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Revil_SH_2147763514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Revil.SH!MTB"
        threat_id = "2147763514"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Revil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"fls\":[\"boot.ini\",\"iconcache.db\",\"bootsect.bak\",\"thumbs.db\"" ascii //weight: 1
        $x_1_2 = "\"dmn\":\"ravensnesthomegoods.com;hypozentrum.com;xn--singlebrsen-vergleich-nec.com;" ascii //weight: 1
        $x_1_3 = "\"prc\":[\"msaccess\",\"infopath\",\"oracle\",\"encsvc\"" ascii //weight: 1
        $x_1_4 = "\"ext\":[\"cpl\",\"ocx\",\"msp\",\"386\",\"cab\",\"cur\",\"mod\"" ascii //weight: 1
        $x_1_5 = "\"nname\":\"{EXT}-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Revil_SI_2147764279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Revil.SI!MTB"
        threat_id = "2147764279"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Revil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 0f b6 c9 03 c1 8a 0a 84 c9 75 ee 15 00 69 c0 ?? ?? ?? ?? 42 0f b6 c9 03 c1 8a 0a 84 c9 75 ee}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4f 3c 81 e6 ff ff 1f 00 33 db 8b 4c 39 78 03 cf 8b 41 24 8b 51 20 03 c7 89 45 f8 03 d7 8b 41 1c 03 c7 89 55 fc 89 45 f4 8b 41 18 89 45 08 85 c0 74 1e 8b 04 9a 03 c7 50 e8 ?? ?? ?? ?? 25 ff ff 1f 00 59 3b c6 74 12 8b 55 fc 43 3b 5d 08 72 e2 33 c0 5f 5e 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Revil_D_2147764526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Revil.D!MTB"
        threat_id = "2147764526"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Revil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DONT try to change files by yourself, DONT use any third party software for restoring your data or antivirus solutions" ascii //weight: 1
        $x_1_2 = "Its in your interests to get your files back. From our side, we (the best specialists) make everything for restoring" ascii //weight: 1
        $x_1_3 = "Now with twice the ransom!" ascii //weight: 1
        $x_1_4 = "tazerface strikes again!" ascii //weight: 1
        $x_1_5 = "You can check it: all files on your system has extension ENCRYPTED" ascii //weight: 1
        $x_1_6 = "Your files are encrypted, and currently unavailable." ascii //weight: 1
        $x_1_7 = "We absolutely do not care about you and your deals, except getting benefits." ascii //weight: 1
        $x_1_8 = "There you can decrypt one file for free. That is our guarantee." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Revil_A_2147780003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Revil.A"
        threat_id = "2147780003"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Revil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 63 6e 61 6d 65 00 00 64 61 74 61 00 00 00 00 66 69 6c 65 73 69 7a 65 00 00 00 00 00 00 00 00 66 72 61 6d 65 73 69 7a 65 00 00 00 00 00 00 00 66 72 61 6d 65 6e 75 6d 00 00 00 00 00 00 00 00 66 69 6c 65 63 72 63 00 66 69 6c 65 6e 61 6d 65 00 00 00 00 6c 6f 63 6b 65 64 00 00 2e 6c 6f 63 6b 00 00 00 2a 00 00 00 25 00 73 00 25 00 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 62 79 74 65 5b 5d 5d 40 28 2c 20 30 20 2a 20 31 6d 62 29 3b 20 53 65 74 2d 43 6f 6e 74 65 6e 74 20 2d 50 61 74 68 20 24 70 72 6f 63 2e 46 69 6c 65 4e 61 6d 65 20 2d 46 6f 72 63 65 20 2d 43 6f 6e 66 69 72 6d 3a 30 20 2d 56 61 6c 75 65 20 24 62 75 66 66 3b 20 52 65 6d 6f 76 65 2d 49 74 65 6d 20 2d 50 61 74 68 20 24 70 72 6f 63 2e 46 69 6c 65 4e 61 6d 65 20 2d 46 6f 72 63 65 20 2d 43 6f 6e 66 69 72 6d 3a 30 20 22 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Revil_A_2147780003_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Revil.A"
        threat_id = "2147780003"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Revil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 8a 1c 39 33 d2 0f b6 cb f7 75 10 8b 45 0c 0f b6 04 02 03 c6 03 c8 0f b6 f1 8b 4d fc 8a 04 3e 88 04 39 41 88 1c 3e 89 4d fc 81 f9 00 01 00 00 72 cd}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 08 40 0f b6 c8 8b 45 08 89 4d 10 8b 5d 10 8a 0c 01 0f b6 c1 03 c6 0f b6 f0 8b 45 08 8a 04 06 88 04 13 8b c2 8b d3 8b 5d 14 88 0c 06}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 04 02 8b 55 0c 0f b6 c9 03 c8 0f b6 c1 8b 4d 08 8a 04 08 32 04 1a 88 03 43 8b 45 10 89 5d 14 83 ef 01 75 ac}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Revil_B_2147780004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Revil.B"
        threat_id = "2147780004"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Revil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 06 4a 6a 08 33 c8 46 5f 8b c1 d1 e9 83 e0 01 f7 d0 40 25 20 83 b8 ed 33 c8 83 ef 01 75 ea 85 d2 75 dc}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 08 6a 2b 58 eb 0c 69 c0 0f 01 00 00 42 0f b6 c9 03 c1 8a 0a 84 c9 75 ee}  //weight: 1, accuracy: High
        $x_1_3 = {05 02 00 00 80 33 c9 53 0f a2 8b f3 5b 8d 5d e8 89 03 8b 45 fc 89 73 04 40 89 4b 08 8b f3 89 53 0c 89 45 fc a5 a5 a5 a5 8b 7d f8 83 c7 10 89 7d f8 83 f8 03 7c ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Revil_C_2147780005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Revil.C"
        threat_id = "2147780005"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Revil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 08 81 f7 ?? ?? ?? ?? 8b 59 28 6a 2b 58 89 45 fc 0f b7 33 66 85 f6 74 2d 8b d0 8d 46 bf 8d 5b 02 66 83 f8 19 77 03 83 ce 20 69 d2 0f 01 00 00 0f b7 c6 0f b7 33 03 d0 66 85 f6 75 de 89 55 fc 8b 55 f8 8b 45 fc 3b c7 74 0f 8b 09 3b ca 75 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Revil_MAK_2147797820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Revil.MAK!MTB"
        threat_id = "2147797820"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Revil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 06 f6 2d [0-4] 8a d0 2a d1 2a 15 [0-4] 3b 0d [0-4] a2 00 88 15 01 74 18 02 c0 2a c2 02 c1 04 [0-1] 83 c6 [0-1] 81 fe [0-4] a2 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Revil_AK_2147913417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Revil.AK"
        threat_id = "2147913417"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Revil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a3 68 fb 48 00 a1 08 70 43 00 a3 38 ac 4b 00 33 c0 39 35 ec 41 49 00 76 1f 8b 0d 38 ac 4b 00 8a 8c 08 ?? ?? ?? ?? 8b 15 68 fb 48 00 88 0c 10 40 3b 05 ec 41 49 00 72 e1 68 ec 41 49 00 68 68 fb 48 00 e8 92 e6 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Revil_PA_2147961481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Revil.PA!MTB"
        threat_id = "2147961481"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Revil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".FIXT" wide //weight: 1
        $x_1_2 = "readme.hta" wide //weight: 1
        $x_1_3 = "startb.bat" wide //weight: 1
        $x_3_4 = "YOUR_FILES_ARE_ENCRYPTED.TXT" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

