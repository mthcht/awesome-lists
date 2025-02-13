rule Worm_Win32_Malas_2147597738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Malas"
        threat_id = "2147597738"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Malas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "333"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "\\svchost.exe" wide //weight: 100
        $x_100_2 = "open=autoply.exe OPEN" ascii //weight: 100
        $x_100_3 = "C:\\WINDOWS\\system32\\cmd.exe" wide //weight: 100
        $x_10_4 = "[autorun]" ascii //weight: 10
        $x_10_5 = "shell\\open\\Default=1" ascii //weight: 10
        $x_10_6 = "shell\\explore=Explore" ascii //weight: 10
        $x_10_7 = "shell\\open\\Command=autoply.exe" ascii //weight: 10
        $x_10_8 = "shell\\explore\\Command=autoply.exe" ascii //weight: 10
        $x_10_9 = "shell\\AutoPlay\\Command=autoply.exe" ascii //weight: 10
        $x_1_10 = "WNetOpenEnumW" ascii //weight: 1
        $x_1_11 = "WNetEnumResourceW" ascii //weight: 1
        $x_1_12 = "NetShareAdd" ascii //weight: 1
        $x_1_13 = "MoveFileW" ascii //weight: 1
        $x_1_14 = "FindFirstFileW" ascii //weight: 1
        $x_1_15 = "FindNextFileW" ascii //weight: 1
        $x_1_16 = "SetProcessShutdownParameters" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 3 of ($x_10_*) and 3 of ($x_1_*))) or
            ((3 of ($x_100_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Malas_A_2147612655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Malas.gen!A"
        threat_id = "2147612655"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Malas"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 f8 04 74 39 83 f8 05 74 34 83 f8 06 74 2f 85 c0 74 2b 83 f8 01 74 26 83 f8 02 74 05 83 f8 03 75 1c}  //weight: 2, accuracy: High
        $x_2_2 = {ff d6 ff 45 b4 8b 45 b4 8b 44 85 a4 85 c0 75 cd ff 45 b8 8b 45 b8 8b 44 85 80 85 c0 89 45 b0 75 b6}  //weight: 2, accuracy: High
        $x_1_3 = {6e 00 6c 00 34 00 30 00 61 00 73 00 32 00 33 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {59 00 61 00 68 00 6f 00 6f 00 64 00 2e 00 4a 00 70 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 00 65 00 78 00 47 00 61 00 6d 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 00 65 00 78 00 53 00 63 00 72 00 65 00 65 00 6e 00 53 00 61 00 76 00 65 00 72 00 2e 00 73 00 63 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {53 00 65 00 78 00 47 00 61 00 6d 00 65 00 4c 00 69 00 73 00 74 00 2e 00 70 00 69 00 66 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 50 00 72 00 6f 00 6d 00 70 00 74 00 2e 00 6c 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Malas_B_2147656270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Malas.gen!B"
        threat_id = "2147656270"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Malas"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ufwatch.pdb" ascii //weight: 1
        $x_1_2 = "Microsoft Shared\\DAO\\svchost.exe" ascii //weight: 1
        $x_1_3 = "shell\\open\\Default=1" ascii //weight: 1
        $x_1_4 = "shell\\explore=explorer(&X)" ascii //weight: 1
        $x_1_5 = "\\svchost.exe -k netsvcs" wide //weight: 1
        $x_1_6 = "autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

