rule Rogue_Win32_SpyAxe_16752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpyAxe"
        threat_id = "16752"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAxe"
        severity = "168"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "malwarecrush.com/download-sd.php?aff=" ascii //weight: 1
        $x_1_2 = "MalwareCrush.exe" ascii //weight: 1
        $x_1_3 = "32eb9f30-2f0a-4ea9-bcba-c9e3da69a046" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_6 = "InternetCloseHandle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_SpyAxe_16752_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpyAxe"
        threat_id = "16752"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAxe"
        severity = "168"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{CompanyNamePutHere} sites to Internet Explorer trusted zone." ascii //weight: 1
        $x_1_2 = "6. Disclaimer of Damages" ascii //weight: 1
        $x_1_3 = "The disclaimers and limitations set forth above will apply regardless of whether You accept {softwareNamePutHere}." ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "Support\\Online Support.lnk" ascii //weight: 1
        $x_1_6 = "successfully installed!" ascii //weight: 1
        $x_1_7 = "%Programfiles%\\" ascii //weight: 1
        $x_1_8 = ".com/support.php" ascii //weight: 1
        $x_1_9 = ".com/userguide.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_SpyAxe_16752_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpyAxe"
        threat_id = "16752"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAxe"
        severity = "168"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7b 38 44 34 34 31 42 43 39 2d 46 38 38 45 2d 34 62 37 30 2d 39 44 30 33 2d 35 37 38 41 38 46 36 31 39 32 42 36 7d 00 00 72 65 67 78 31 2e 62 61 74 00 00 00 72 65 67 31 2e 72 65 67 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 7b 32 43 37 30 31 36 38 42 2d 39 37 43 45 2d 34 66 33 31 2d 42 38 35 44 2d 31 46 45 43 35 30 30 32 37 32 31 44 7d 00 00 68 74 74 70 3a 2f 2f 74 68 65 6f 6e 6c 79 62 00 6f 6f 6b 6d 61 72 6b 2e 63 6f 6d 2f 69 00 00 00 6e 2e 63 67 69 3f 31 00 31 26 67 72 6f 75 00 00 70 3d 61 64 76 30 30 31 00 00 00 00 55 52 4c 00 47 65 6e 65 72 61 6c 31 00 00 00 00 68 74 74 70 3a 2f 2f 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 3f 74 69 6d 65 3d 25 64 00 00 00 54 69 6d 65 55 72 6c 00 53 6f 66 74 77 61 72 65 5c 43 72 79 73 74 61 6c 52 65 61 6c 69 74 79 43 6c 65 61 6e 65 72 00 00 76 61 6c 00 25 70 72 6f 67 72 61 6d 66 69 6c 65 73 25 5c 73 70 79 62 75 72 6e 65 72 5c 73 70 79 62 75 72 6e 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 78 3a 5c 44 65 76 5f 43 50 50 5c 57 6f 72 6b 5c 56 53 5f 4b 6e 7a 53 74 72 5f 41 64 77 61 72 65 5c 52 65 6c 65 61 73 65 5c 56 53 5f 57 6f 72 6b 31 2e 70 64 62 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_SpyAxe_16752_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpyAxe"
        threat_id = "16752"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAxe"
        severity = "168"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 53 00 70 00 79 00 42 00 75 00 72 00 6e 00 65 00 72 00 20 00 49 00 6e 00 63 00 ?? ?? ?? ?? ?? ?? ?? ?? 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 ?? ?? ?? ?? 53 00 70 00 79 00 42 00 75 00 72 00 6e 00 65 00 72 00}  //weight: 5, accuracy: Low
        $x_5_2 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 ?? ?? 53 00 70 00 79 00 42 00 75 00 72 00 6e 00 65 00 72 00 ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 ?? ?? 53 00 70 00 79 00 42 00 75 00 72 00 6e 00 65 00 72 00 20 00 49 00 6e 00 63 00 ?? ?? ?? ?? ?? ?? ?? ?? 4c 00 65 00 67 00 61 00 6c 00 54 00 72 00 61 00 64 00 65 00 6d 00 61 00 72 00 6b 00 73 00 ?? ?? ?? ?? 53 00 70 00 79 00 42 00 75 00 72 00 6e 00 65 00 72 00}  //weight: 5, accuracy: Low
        $x_3_3 = {42 61 64 43 6f 64 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 53 70 79 42 75 72 6e 65 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 45 2d 4d 61 69 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 52 65 67 69 73 74 65 72 65 64 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6f 6e 66 69 67 2e 75 64 62 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 42 75 79 4f 6e 6c 69 6e 65}  //weight: 3, accuracy: Low
        $x_1_4 = "http://www.spyburner.com/activate.php?time=" ascii //weight: 1
        $x_1_5 = "\\Software\\SpyBurner" ascii //weight: 1
        $x_1_6 = "http://ag.ru" ascii //weight: 1
        $x_1_7 = "www.fuckmyass.com/" ascii //weight: 1
        $x_1_8 = "@fuckmyass.com[1].txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

