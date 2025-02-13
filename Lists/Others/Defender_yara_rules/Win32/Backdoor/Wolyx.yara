rule Backdoor_Win32_Wolyx_A_2147647456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wolyx.A"
        threat_id = "2147647456"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wolyx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{AFAFB2EE-837C-4EA5-B933-998F94AEC654}" ascii //weight: 1
        $x_1_2 = "Kunming Wuhua District YanXing Technology Sales Department" ascii //weight: 1
        $x_1_3 = {46 8b c6 66 05 87 69}  //weight: 1, accuracy: High
        $x_3_4 = {3d c9 04 00 00 75 09 33 db eb 05 bb 01 00 00 00}  //weight: 3, accuracy: High
        $x_3_5 = {83 fa 10 7f 0f 74 61 4a 74 1c 4a 74 27 83 ea 04 74 1b eb 40 81 ea 11 01 00 00}  //weight: 3, accuracy: High
        $x_3_6 = {8b 95 b4 fe ff ff 89 55 e0 8b 95 b8 fe ff ff 89 55 e4}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Wolyx_A_2147647557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wolyx.A!dll"
        threat_id = "2147647557"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wolyx"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "{AFAFB2EE-837C-4EA5-B933-998F94AEC654}\\" ascii //weight: 4
        $x_4_2 = "AsutatSsecivreSmunE" ascii //weight: 4
        $x_4_3 = ":(Floopy)" ascii //weight: 4
        $x_4_4 = " cloudcom2.dll" ascii //weight: 4
        $x_2_5 = "Passwords of Auto Complete" ascii //weight: 2
        $x_2_6 = "Think Space" ascii //weight: 2
        $x_2_7 = "Protocol_Catalog9\\Catalog_Entries" ascii //weight: 2
        $x_1_8 = "theworld.exe" ascii //weight: 1
        $x_1_9 = "ttraveler.exe" ascii //weight: 1
        $x_1_10 = "TSendDriverDirFilesThread" ascii //weight: 1
        $x_1_11 = "TSendKeyLogInfoThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*) and 4 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Wolyx_B_2147656486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wolyx.B"
        threat_id = "2147656486"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wolyx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 75 63 6b 79 6f 75 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 73 73 65 63 65 73 00 ff ff ff ff 0a 00 00 00 73 70 69 64 65 72 67 61 74 65 00 00 ff ff ff ff 08 00 00 00 75 66 73 65 61 67 6e 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {49 45 69 6e 66 6f 2e 64 6c 6c 00 57 53 50 53 74 61 72 74 75 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Wolyx_B_2147656516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wolyx.B"
        threat_id = "2147656516"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wolyx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 02 6a 00 6a 02 68 00 00 00 40 a1 ?? ?? ?? ?? 8b 00 50 e8 ?? ?? ?? ?? 8b f0 83 fe ff 74 ?? 6a 00 8d 45 fc 50 57 8d 45 f8 e8 ?? ?? ?? ?? 50 56 e8 ?? ?? ?? ?? 56 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {64 ff 30 64 89 20 c6 45 f7 00 8d 45 ec 50 68 3f 00 0f 00 6a 00 8b 45 0c e8 ?? ?? ?? ?? 50 8b 45 10 50 a1 ?? ?? ?? ?? 8b 00 ff d0 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = "AD18BB45B27C8946AD19A0768E749458AE29A05BB2478847AF02A15A8D778E" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

