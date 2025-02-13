rule Backdoor_Win32_NetWiredRC_A_2147661506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NetWiredRC.A"
        threat_id = "2147661506"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWiredRC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 74 74 70 3a 2f 2f 25 73 25 73 07 25 73 00 47 45 54 20 25 73 20 48 54 54 50}  //weight: 5, accuracy: High
        $x_5_2 = {5b 25 2e 32 64 2f 25 2e 32 64 2f 25 64 ?? 25 2e 32 64 3a 25 2e 32 64 3a 25 2e 32 64 5d}  //weight: 5, accuracy: Low
        $x_5_3 = {25 6c 6c 75 20 25 63 25 73 07 25 49 36 34 75 07 25 49 36 34 75 20 72 62}  //weight: 5, accuracy: High
        $x_1_4 = "%s\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_5 = "%s\\Chromium\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_6 = "select *  from moz_logins" ascii //weight: 1
        $x_1_7 = "\\Internet Explorer\\IntelliForms\\Storage2" ascii //weight: 1
        $x_1_8 = "%s\\Thunderbird\\profiles.ini" ascii //weight: 1
        $x_1_9 = "%s\\Opera\\Opera\\profile\\wand.dat" ascii //weight: 1
        $x_1_10 = "%s\\.purple\\accounts.xml" ascii //weight: 1
        $x_1_11 = "%s\\Mozilla\\Firefox\\profiles.ini" ascii //weight: 1
        $x_1_12 = "%s\\Mozilla\\SeaMonkey\\profiles.ini" ascii //weight: 1
        $x_10_13 = "RGI28DQ30QB8Q1F7" ascii //weight: 10
        $x_10_14 = {0f b7 d1 69 d2 69 90 00 00 c1 e1 10 01 ca 89}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_NetWiredRC_B_2147679567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NetWiredRC.B"
        threat_id = "2147679567"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWiredRC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c7 44 24 04 03 00 00 00 89 14 24 e8 ?? ?? ?? ?? 43 81 fb ff 00 00 00 75 d8 31 d2 31 c9 eb 14 0f b6 82 ?? ?? ?? ?? b9 ff 00 00 00 29 c1 8a 89}  //weight: 3, accuracy: Low
        $x_1_2 = {73 65 6c 65 63 74 20 2a 20 20 66 72 6f 6d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 5c 4f 70 65 72 61 5c 4f 70 65 72 61 5c 70 72 6f 66 69 6c 65 5c 77 61 6e 64 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 5c 2e 70 75 72 70 6c 65 5c 61 63 63 6f 75 6e 74 73 2e 78 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 69 6e 64 6f 77 73 4c 69 76 65 3a 6e 61 6d 65 3d 2a 00}  //weight: 1, accuracy: High
        $x_1_6 = {61 62 65 32 38 36 39 66 2d 39 62 34 37 2d 34 63 64 39 2d 61 33 35 38 2d 63 32 32 39 30 34 64 62 61 37 66 37 00}  //weight: 1, accuracy: High
        $x_1_7 = {25 73 5c 43 68 72 6f 6d 69 75 6d 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_8 = {5b 42 61 63 6b 73 70 61 63 65 5d 00 5b 45 6e 74 65 72 5d 00 5b 54 61 62 5d 00}  //weight: 1, accuracy: High
        $x_1_9 = {25 73 07 25 73 07 25 73 07 25 49 36 34 75 07 25 49 36 34 75 07 25 49 36 34 75 07}  //weight: 1, accuracy: High
        $x_1_10 = {57 49 4e 4e 54 00 4c 41 4e 4d 41 4e 4e 54 00 53 45 52 56 45 52 4e 54 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_NetWiredRC_C_2147691862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NetWiredRC.C"
        threat_id = "2147691862"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWiredRC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 65 6c 65 63 74 20 2a 20 20 66 72 6f 6d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 5c 4f 70 65 72 61 5c 4f 70 65 72 61 5c 70 72 6f 66 69 6c 65 5c 77 61 6e 64 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 5c 2e 70 75 72 70 6c 65 5c 61 63 63 6f 75 6e 74 73 2e 78 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 69 6e 64 6f 77 73 4c 69 76 65 3a 6e 61 6d 65 3d 2a 00}  //weight: 1, accuracy: High
        $x_1_5 = {61 62 65 32 38 36 39 66 2d 39 62 34 37 2d 34 63 64 39 2d 61 33 35 38 2d 63 32 32 39 30 34 64 62 61 37 66 37 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 5c 43 68 72 6f 6d 69 75 6d 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_7 = {5b 42 61 63 6b 73 70 61 63 65 5d 00 5b 45 6e 74 65 72 5d 00 5b 54 61 62 5d 00}  //weight: 1, accuracy: High
        $x_1_8 = {25 73 07 25 73 07 25 73 07 25 49 36 34 75 07 25 49 36 34 75 07 25 49 36 34 75 07}  //weight: 1, accuracy: High
        $x_1_9 = {57 49 4e 4e 54 00 4c 41 4e 4d 41 4e 4e 54 00 53 45 52 56 45 52 4e 54 00}  //weight: 1, accuracy: High
        $x_1_10 = {5b 25 2e 32 64 2f 25 2e 32 64 2f 25 64 ?? 25 2e 32 64 3a 25 2e 32 64 3a 25 2e 32 64 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_NetWiredRC_C_2147696815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NetWiredRC.C!Lowfi"
        threat_id = "2147696815"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWiredRC"
        severity = "Critical"
        info = "Lowfi: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "200"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 1b 8a 44 0f ff 3c 7a 75 d3 4a 8a 04 17 fe c0 88 04 17 3c 7b 75 b0 c6 04 17 41 eb ed 89 fb 89 f7 b9 21 01 00 00 31 d2 ac}  //weight: 1, accuracy: High
        $x_1_2 = {75 7a 8a 04 17 fe c0 88 04 17 29 c0 83 c0 06 89 c1 53 56 8a 44 0e ff 32 44 0f ff 5e 5b 3a 44 0b ff 75 04 e2 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_NetWiredRC_D_2147697385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NetWiredRC.D"
        threat_id = "2147697385"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWiredRC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 36 77 28 28 37 37 37 36 35 7a 3b 31 2b 39 37 [0-255] 5a 58 50 45 57 58 5a 58 50 45 57 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_NetWiredRC_E_2147710321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NetWiredRC.E"
        threat_id = "2147710321"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWiredRC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {aa aa aa aa aa aa aa 81}  //weight: 1, accuracy: High
        $x_1_2 = {02 64 8b 0d 18 00 00 00 81 ?? ?? ?? ?? 02 81}  //weight: 1, accuracy: Low
        $x_1_3 = {02 8b 49 30 81 ?? ?? ?? ?? 02}  //weight: 1, accuracy: Low
        $x_1_4 = {02 02 59 02 90 81}  //weight: 1, accuracy: High
        $x_1_5 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_NetWiredRC_AB_2147734617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NetWiredRC.AB!bit"
        threat_id = "2147734617"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWiredRC"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 17 fe c0 88 04 17 29 c0 83 c0 06 89 c1 53 56 8a 44 0e ff 32 44 0f ff 5e 5b 3a 44 0b ff}  //weight: 1, accuracy: High
        $x_1_2 = {8a 44 0f ff 3c 7a 75 ?? 4a 8a 04 17 fe c0 88 04 17 3c 7b 75 ?? c6 04 17 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_NetWiredRC_2147740986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NetWiredRC!MTB"
        threat_id = "2147740986"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWiredRC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 1c 17 81 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 31 f3 81 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 01 1c 10}  //weight: 5, accuracy: Low
        $x_5_2 = "LEoCwf77eHev1FEFC0wGYWZF8mfBqmLC229" wide //weight: 5
        $x_5_3 = "ipIJ5khkM33u0qZJiHVV8hd9gGQUi59" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_NetWiredRC_A_2147772396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NetWiredRC.A!MTB"
        threat_id = "2147772396"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWiredRC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegSvcs.exe" ascii //weight: 1
        $x_1_2 = "\\asgreg.exe" ascii //weight: 1
        $x_1_3 = "*/*G*/*e*/*t*/*M*/*e*/*t*/*h*/*o*/*d" ascii //weight: 1
        $x_1_4 = "2154D82A4F0340AADF0AB5D76D6F8F0F2E6CE3297517C3E9E54AEE6F59F0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

