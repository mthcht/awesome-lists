rule Ransom_Win32_Troldesh_A_2147691978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Troldesh.A"
        threat_id = "2147691978"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Troldesh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "01092015.exe" wide //weight: 1
        $x_1_2 = "\\Documents\\documenti_zagruska\\" wide //weight: 1
        $x_1_3 = {28 a8 b0 3a 98 c4 1c ab a3 a0 11 cb 17 31 62 59 44 3a c8 b0 3d ba ac c3 aa 4d 35 47 48 35 31 43 34 44 36 39 4b 35 4c 32 43 31 56 34 46 37 53 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Troldesh_A_2147691978_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Troldesh.A"
        threat_id = "2147691978"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Troldesh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Walker:" ascii //weight: 1
        $x_1_2 = "Watcher:" ascii //weight: 1
        $x_1_3 = "wb2|cdr|srw|p7b|odm|mdf|p7c|3fr|" ascii //weight: 1
        $x_1_4 = {72 65 67 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_5 = "send the following code:" ascii //weight: 1
        $x_1_6 = {52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 77 00 68 00 69 00 63 00 68 00 20 00 79 00 6f 00 75 00 20 00 63 00 61 00 6e 00 20 00 66 00 69 00 6e 00 64 00 20 00 6f 00 6e 00 20 00 61 00 6e 00 79 00 20 00 6f 00 66 00 20 00 79 00 6f 00 75 00 72 00 20 00 64 00 69 00 73 00 6b 00 73 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "--ignore-missing-torrc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Troldesh_B_2147708428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Troldesh.B"
        threat_id = "2147708428"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Troldesh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 65 74 77 6f 72 6b 53 75 62 73 79 73 74 65 6d 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 70 64 2e 70 68 70 3f 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 63 61 6e 5f 70 6f 72 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 74 61 73 6b 2e 70 68 70 3f 00}  //weight: 1, accuracy: High
        $x_1_5 = "Dear AV analysts," ascii //weight: 1
        $x_1_6 = {2e 6f 6e 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_7 = "\\Csrss\\Configuration\\" ascii //weight: 1
        $x_1_8 = {43 6c 69 65 6e 74 20 53 65 72 76 65 72 20 52 75 6e 74 69 6d 65 20 53 75 62 73 79 73 74 65 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_Win32_Troldesh_C_2147712194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Troldesh.C"
        threat_id = "2147712194"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Troldesh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Startup)%\\Decryption instructions.txt" wide //weight: 1
        $x_1_2 = "Global\\syncronize_CRYSS0" wide //weight: 1
        $x_1_3 = {2e 00 43 00 72 00 79 00 53 00 69 00 53 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "doc(.doc;.docx;.pdf;.xls;.xlsx;.ppt;)arc(.zip;.rar;.bz2;" wide //weight: 1
        $x_1_5 = "submit=submit&id=CRYSS0-" ascii //weight: 1
        $x_1_6 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Troldesh_C_2147712194_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Troldesh.C"
        threat_id = "2147712194"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Troldesh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = Int2Str(\"" ascii //weight: 1
        $x_1_2 = {58 00 51 00 38 00 7a 00 68 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "*\\AD:\\Downloads\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Troldesh_A_2147716144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Troldesh.A!!Troldesh.gen!A"
        threat_id = "2147716144"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Troldesh"
        severity = "Critical"
        info = "Troldesh: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Walker:" ascii //weight: 1
        $x_1_2 = "Watcher:" ascii //weight: 1
        $x_1_3 = "wb2|cdr|srw|p7b|odm|mdf|p7c|3fr|" ascii //weight: 1
        $x_1_4 = {72 65 67 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_5 = "send the following code:" ascii //weight: 1
        $x_1_6 = "desktop.ini|boot.ini|BOOT.INI" ascii //weight: 1
        $x_1_7 = "--ignore-missing-torrc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Troldesh_E_2147720809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Troldesh.E"
        threat_id = "2147720809"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Troldesh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 72 65 67 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 70 72 6f 67 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 65 72 72 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 63 6d 64 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 73 79 73 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 73 68 64 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 73 68 62 3d 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 25 30 32 68 68 58 00}  //weight: 1, accuracy: High
        $x_1_9 = ".no_more_ransom" ascii //weight: 1
        $x_1_10 = ".tyson" ascii //weight: 1
        $x_3_11 = "desktop.ini|boot.ini|Bootfont.bin|ntuser.ini|NTUSER.DAT|IconCache.db" ascii //weight: 3
        $x_2_12 = "a4ad4ip2xzclh6fd.onion" ascii //weight: 2
        $x_2_13 = "areukonpcymxABE3KMHOPCTYX" ascii //weight: 2
        $x_1_14 = "Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_15 = "List Shadows" ascii //weight: 1
        $x_1_16 = "SELECT * FROM Win32_OperatingSystem" ascii //weight: 1
        $x_1_17 = "SOFTWARE\\System32\\Configuration\\" ascii //weight: 1
        $x_1_18 = "csrss.lnk" ascii //weight: 1
        $x_1_19 = "Client Server Runtime Subsystem" ascii //weight: 1
        $x_1_20 = "Watcher:" ascii //weight: 1
        $x_1_21 = "Walker:" ascii //weight: 1
        $x_1_22 = "--ignore-missing-torrc" ascii //weight: 1
        $x_1_23 = "--SOCKSPort" ascii //weight: 1
        $x_1_24 = "--DataDirectory" ascii //weight: 1
        $x_1_25 = "--bridge" ascii //weight: 1
        $x_1_26 = "can not create dir" ascii //weight: 1
        $x_1_27 = "can not copy file" ascii //weight: 1
        $x_1_28 = "can not add to autorun" ascii //weight: 1
        $x_1_29 = "can not save value (mark)" ascii //weight: 1
        $x_3_30 = {c6 45 fc 04 8b 06 51 8b ce ff 50 04 57 50 8d 45 ?? 50 c6 45 fc 05}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Troldesh_E_2147720810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Troldesh.E!!Troldesh.gen!A"
        threat_id = "2147720810"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Troldesh"
        severity = "Critical"
        info = "Troldesh: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 72 65 67 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 70 72 6f 67 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 65 72 72 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 63 6d 64 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 73 79 73 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 73 68 64 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 73 68 62 3d 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 25 30 32 68 68 58 00}  //weight: 1, accuracy: High
        $x_1_9 = ".no_more_ransom" ascii //weight: 1
        $x_1_10 = ".tyson" ascii //weight: 1
        $x_3_11 = "desktop.ini|boot.ini|Bootfont.bin|ntuser.ini|NTUSER.DAT|IconCache.db" ascii //weight: 3
        $x_2_12 = "a4ad4ip2xzclh6fd.onion" ascii //weight: 2
        $x_2_13 = "areukonpcymxABE3KMHOPCTYX" ascii //weight: 2
        $x_1_14 = "Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_15 = "List Shadows" ascii //weight: 1
        $x_1_16 = "SELECT * FROM Win32_OperatingSystem" ascii //weight: 1
        $x_1_17 = "SOFTWARE\\System32\\Configuration\\" ascii //weight: 1
        $x_1_18 = "csrss.lnk" ascii //weight: 1
        $x_1_19 = "Client Server Runtime Subsystem" ascii //weight: 1
        $x_1_20 = "Watcher:" ascii //weight: 1
        $x_1_21 = "Walker:" ascii //weight: 1
        $x_1_22 = "--ignore-missing-torrc" ascii //weight: 1
        $x_1_23 = "--SOCKSPort" ascii //weight: 1
        $x_1_24 = "--DataDirectory" ascii //weight: 1
        $x_1_25 = "--bridge" ascii //weight: 1
        $x_1_26 = "can not create dir" ascii //weight: 1
        $x_1_27 = "can not copy file" ascii //weight: 1
        $x_1_28 = "can not add to autorun" ascii //weight: 1
        $x_1_29 = "can not save value (mark)" ascii //weight: 1
        $x_3_30 = {c6 45 fc 04 8b 06 51 8b ce ff 50 04 57 50 8d 45 ?? 50 c6 45 fc 05}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Troldesh_AE_2147735452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Troldesh.AE!bit"
        threat_id = "2147735452"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Troldesh"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 8b 02 8b 4d fc 8d 94 01 ?? ?? ?? ?? 8b 45 08 89 10 8b 4d 08 8b 11 81 ea ?? ?? ?? ?? 8b 45 08 89 10}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 11 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 e8 01 a3 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 83 c2 01 a1 ?? ?? ?? ?? 8b ff 8b ca a3 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 8b ff 01 05 ?? ?? ?? ?? 8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

