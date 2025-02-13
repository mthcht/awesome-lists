rule TrojanDownloader_Win32_Brantall_A_2147683857_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Brantall.A"
        threat_id = "2147683857"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Brantall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3c 43 41 4d 50 41 49 47 4e 5f 49 44 3e 3c 21 5b 43 44 41 54 41 5b [0-4] 5d 5d 3e 3c 2f 43 41 4d 50 41 49 47 4e 5f 49 44 3e 3c 43 41 4d 50 41 49 47 4e 5f 53 55 42 49 44 3e 3c 21 5b 43 44 41 54 41 5b}  //weight: 2, accuracy: Low
        $x_2_2 = "%s?cmp=%s&sub=%s&rkey=%s" wide //weight: 2
        $x_1_3 = "/installer/bootstrap.php" wide //weight: 1
        $x_1_4 = "IBUpdaterService" wide //weight: 1
        $x_1_5 = "is_component_offered" ascii //weight: 1
        $x_1_6 = "get_component_exe_name" ascii //weight: 1
        $x_1_7 = "get_campaign_id" ascii //weight: 1
        $x_1_8 = "component_service@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Brantall_D_2147684061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Brantall.D"
        threat_id = "2147684061"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Brantall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0e 88 59 ?? b9 ?? ?? ?? ?? 2b c8 8b d7 8a 1c 01 80 f3 ?? 88 18 40 4a 75 f4 57 8b ce}  //weight: 1, accuracy: Low
        $x_1_2 = {72 63 34 28 31 78 2c 63 68 61 72 29 00}  //weight: 1, accuracy: High
        $x_1_3 = {2d 00 6e 00 6f 00 64 00 65 00 63 00 00 00 00 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Brantall_E_2147684197_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Brantall.E"
        threat_id = "2147684197"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Brantall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 00 73 00 3f 00 63 00 6d 00 70 00 3d 00 25 00 73 00 26 00 73 00 75 00 62 00 3d 00 25 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = "InstallBrainService.exe" wide //weight: 2
        $x_1_3 = "/installer/bootstrap.php" wide //weight: 1
        $x_1_4 = "%s\\component_%d" wide //weight: 1
        $x_1_5 = "%s\\component_%s_%d" wide //weight: 1
        $x_1_6 = {2e 00 64 00 65 00 63 00 72 00 70 00 74 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

