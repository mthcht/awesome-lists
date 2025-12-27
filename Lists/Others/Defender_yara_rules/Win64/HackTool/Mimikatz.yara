rule HackTool_Win64_Mimikatz_A_2147723337_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz.A"
        threat_id = "2147723337"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppData\\Roaming\\FileZilla.dat" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Microsoft\\Credential" ascii //weight: 1
        $x_1_3 = "Application Data\\Thunderbird\\Profiles" ascii //weight: 1
        $x_1_4 = "AppData\\Roaming\\Thunderbird\\Profiles" ascii //weight: 1
        $x_1_5 = "AppData\\Roaming\\Mozilla\\Firefox\\Profiles" ascii //weight: 1
        $x_1_6 = "Application Data\\Mozilla\\Firefox\\Profiles" ascii //weight: 1
        $x_1_7 = "Outlook\\Profiles\\Outlook" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\RealVNC\\WinVNC4" ascii //weight: 1
        $x_1_9 = "AdminPassword" ascii //weight: 1
        $x_1_10 = "SOFTWARE\\TightVNC\\Server" ascii //weight: 1
        $x_1_11 = "uvnc bvba\\UltraVNC\\UltraVNC.ini" ascii //weight: 1
        $x_1_12 = "AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data" ascii //weight: 1
        $x_1_13 = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins" ascii //weight: 1
        $x_1_14 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" ascii //weight: 1
        $x_1_15 = "Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\" ascii //weight: 1
        $x_1_16 = "Appdata\\Local\\Google\\Chrome\\User Data\\Default\\" ascii //weight: 1
        $x_1_17 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" ascii //weight: 1
        $x_1_18 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" ascii //weight: 1
        $x_1_19 = "AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat" ascii //weight: 1
        $x_1_20 = "SELECT origin_url, username_value, password_value FROM logins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule HackTool_Win64_Mimikatz_G_2147781484_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz.gen!G"
        threat_id = "2147781484"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 01 00 c0 0f 84 ?? ?? ?? ?? 81 ?? 4b 00 00 c0 0f 84 [0-64] e9 ?? 00 00 00 81 ?? 4b 00 00 c0 0f 84 [0-64] ba ff ff 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {01 00 00 c0 48 85 c9 0f 84 [0-96] 0f b7 03 83 f8 21 74 1a 83 f8 2a 74 0a 48 8b cb e8 ?? 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b da 83 f9 03 75 [0-64] 45 33 c9 45 33 c0 33 d2 b9 85 04 00 00 ff 15 ?? ?? ?? ?? 33 c0 48 83 c4 20 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Mimikatz_G_2147781484_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz.gen!G"
        threat_id = "2147781484"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 00 00 c0 48 85 c9 0f 84 [0-96] 48 8b d8 48 85 ?? 74 35 66 83 3b 21 74 1b 66 83 3b 2a 74 0a 48 8b cb e8 ?? 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b da 83 f9 03 75 [0-64] 45 33 c9 45 33 c0 33 d2 b9 85 04 00 00 ff 15 ?? ?? ?? ?? 33 c0 48 83 c4 20 5b c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 33 41 bf 2c 17 5a e3 49 33 c7 48 89 03 0f 84 ?? ?? ?? ?? 48 8d 45 77 be 08 00 00 00 44 8b c6 48 89 44 24 20 48 8b d3 48 8d 4c 24 20 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Mimikatz_G_2147781484_2
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz.gen!G"
        threat_id = "2147781484"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 01 00 c0 0f 84 ?? ?? ?? ?? 81 ?? 4b 00 00 c0 0f 84 [0-64] e9 ?? 00 00 00 81 ?? 4b 00 00 c0 0f 84 [0-64] ba ff ff 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {01 00 00 c0 48 85 c9 0f 84 [0-96] 48 8b d8 48 85 ?? 74 35 66 83 3b 21 74 1b 66 83 3b 2a 74 0a 48 8b cb e8 ?? 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b da 83 f9 03 75 [0-64] 45 33 c9 45 33 c0 33 d2 b9 85 04 00 00 ff 15 ?? ?? ?? ?? 33 c0 48 83 c4 20 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Mimikatz_H_2147784025_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz.gen!H"
        threat_id = "2147784025"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 22 00 00 00 48 89 44 24 ?? 33 d2 48 8b cb c6 44 24 ?? 00 c7 44 24 ?? 00 01 00 00 ff 15 ?? ?? ?? ?? 8b f8 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 03 c1 22 00 3b c2 0f 87 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? ba 43 c0 22 00 3b c2 0f 87 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 2d 03 c0 22 00 0f 84 ?? ?? ?? ?? 83 e8 04}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b d1 41 b8 69 77 69 6b 33 c9 ff 15 ?? ?? ?? ?? 48 89 45 00}  //weight: 1, accuracy: Low
        $x_1_4 = {ba 69 77 69 6b 48 8b cf ff 15 ?? ?? ?? ?? 8b de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Mimikatz_H_2147784025_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz.gen!H"
        threat_id = "2147784025"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 0b 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 48 8b 4c 24 ?? 48 8d 44 24 ?? 45 33 c9 48 89 44 24 ?? 48 83 64 24 ?? 00 83 64 24 ?? 00 48 83 64 24 ?? 00 83 64 24 ?? 00 41 8d 51 02 45 33 c0 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b8 58 1b 00 00 66 41 3b c0 73 ?? 48 8d ?? ?? ?? ?? ?? eb ?? b9 40 1f 00 00 66 3b c1 73 ?? 48 8d ?? ?? ?? ?? ?? eb ?? b9 b8 24 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 8d 41 04 ff 15 ?? ?? ?? ?? 41 3b c6 0f 84 ?? ?? ?? ?? 8b 54 24 ?? bf 40 00 00 00 48 c1 e2 04 8b cf ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = "lsasrv!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Mimikatz_B_2147827386_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz.B"
        threat_id = "2147827386"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f6 46 24 02 0f 84 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {f6 46 24 0a 0f 84 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {f6 45 24 02 0f 84 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule HackTool_Win64_Mimikatz_D_2147827387_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz.D"
        threat_id = "2147827387"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {24 43 72 64 41 ff 15}  //weight: 10, accuracy: High
        $x_10_2 = {24 43 72 64 41 48 ff 15}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Mimikatz_I_2147827388_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz.I"
        threat_id = "2147827388"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f3 0f 6f 6c 24 30 f3 0f 7f 2d}  //weight: 10, accuracy: High
        $x_10_2 = {0f 10 45 f0 66 48 0f 7e c0 0f 11 05}  //weight: 10, accuracy: High
        $x_10_3 = {48 8b fa 48 8b f1 eb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule HackTool_Win64_Mimikatz_K_2147827389_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz.K"
        threat_id = "2147827389"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0b 06 07 01 08 0a 0e 00 03 05 02 0f 0d 09 0c 04}  //weight: 10, accuracy: High
        $x_10_2 = {bb 03 00 00 c0 e9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Mimikatz_C_2147830968_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz.C"
        threat_id = "2147830968"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 20 00 [0-64] 77 00 69 00 74 00 68 00 20 00 6b 00 65 00 6b 00 65 00 6f 00}  //weight: 10, accuracy: Low
        $x_1_2 = "gentilkiwi.com" wide //weight: 1
        $x_1_3 = "Benjamin DELPY" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_Mimikatz_IB_2147850503_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz.gen!IB"
        threat_id = "2147850503"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ice_types.secrets.mimikatz.MimikatzResult" ascii //weight: 1
        $x_1_2 = "MimiArgs" ascii //weight: 1
        $x_1_3 = "mimidrv.sys" ascii //weight: 1
        $x_1_4 = "vaultcli" ascii //weight: 1
        $x_1_5 = "ClearThreadLocalFiberCallbacks" ascii //weight: 1
        $x_1_6 = "icekatz_run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Mimikatz_G_2147937867_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz.G"
        threat_id = "2147937867"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8d 6e 30 48 8d 0d}  //weight: 10, accuracy: High
        $x_10_2 = {48 8d 94 24 b0 00 00 00 48 8d 0d}  //weight: 10, accuracy: High
        $x_10_3 = {4c 8d 85 30 01 00 00 48 8d 15}  //weight: 10, accuracy: High
        $x_10_4 = {0f b6 4c 24 30 85 c0 0f 45 cf 8a c1}  //weight: 10, accuracy: High
        $x_10_5 = {44 8b 45 80 85 c0 0f 84}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule HackTool_Win64_Mimikatz_H_2147937868_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz.H"
        threat_id = "2147937868"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b9 14 00 00 00 f3 aa 48 8d 3d}  //weight: 10, accuracy: High
        $x_10_2 = {48 8b ca f3 aa 48 8d 3d}  //weight: 10, accuracy: High
        $x_10_3 = {8b ca f3 aa 48 8d 3d}  //weight: 10, accuracy: High
        $x_10_4 = {8d 50 14 8b ca 44 8d 48 01 44}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Mimikatz_MX_2147956811_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz.MX!MTB"
        threat_id = "2147956811"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mimikatz for Windows" wide //weight: 1
        $x_1_2 = "kiwi flavor" wide //weight: 1
        $x_1_3 = "Build with love for POC only" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Mimikatz_AMTB_2147959658_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mimikatz!AMTB"
        threat_id = "2147959658"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "x64/mimikatz.exe" ascii //weight: 4
        $x_4_2 = "Executing Mimikatz" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

