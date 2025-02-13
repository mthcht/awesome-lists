rule TrojanDownloader_Win32_Horst_B_2147600535_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Horst.B"
        threat_id = "2147600535"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "%s + CRACK + ACTIVATOR.EXE" ascii //weight: 1
        $x_1_3 = "%s + CRACK + NOCD.exe" ascii //weight: 1
        $x_1_4 = "%s - NoCD Crack KeyGen.exe" ascii //weight: 1
        $x_1_5 = "back.hasteman.com" ascii //weight: 1
        $x_1_6 = "ads.zablen.com" ascii //weight: 1
        $x_1_7 = "rel.statadd.com/d/dn/dll/zlib1.dll" ascii //weight: 1
        $x_1_8 = "CreateMutexA" ascii //weight: 1
        $x_1_9 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanDownloader_Win32_Horst_J_2147602379_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Horst.J"
        threat_id = "2147602379"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 e4 f8 81 ec 34 03 00 00 a1 ?? ?? ?? ?? 53 56 57 33 f6 89 84 24 3c 03 00 00 33 c0 89 74 24 68 b9 b2 00 00 00 8d 7c 24 6c f3 ab b9 11 00 00 00 8d 7c 24 20 f3 ab 8d 4c 24 0c 51 8b 4d 08 89 44 24 10 8d 54 24 24 52 56 56 89 44 24 20 89 44 24 24 6a 04 89 44 24 2c 8b 45 18 50 56 56 51 56 89 74 24 44 c7 44 24 48 44 00 00 00 66 c7 44 24 78 05 00 ff 15 ?? ?? ?? ?? 85 c0 75 1f 56 ff 15 ?? ?? ?? ?? b8 01 00 00 00 8b 8c 24 3c 03 00 00 e8 ?? ?? ?? ?? 5f 5e 5b 8b e5 5d c3 ff 15 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 56 ff d3 56 ff 55 1c 8b 55 14 8b f0 56 52}  //weight: 1, accuracy: Low
        $x_1_2 = "InternetCloseHandle" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "InternetReadFile" ascii //weight: 1
        $x_1_5 = "OpenMutexA" ascii //weight: 1
        $x_1_6 = "ResumeThread" ascii //weight: 1
        $x_1_7 = {8b 54 24 10 52 ff 15 ?? ?? ?? ?? 83 f8 ff 75 18 b8 07 00 00 00 8b 8c 24 3c 03 00 00 e8 ?? ?? ?? ?? 5f 5e 5b 8b e5 5d c3 8b 35 ?? ?? ?? ?? ff d6 8b 45 10 85 c0 74 0d 8b 44 24 10 6a ff 50 ff 15 ?? ?? ?? ?? ff d6 8b 8c 24 3c 03 00 00 33 c0 e8 ?? ?? ?? ?? 5f 5e 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Horst_K_2147602534_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Horst.K"
        threat_id = "2147602534"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 04 01 00 00 68 50 ac 40 00 68 ?? ?? 40 00 ff 15 ?? 80 40 00 ((??) ff d6 68 ?? ??|68 ?? ??)}  //weight: 1, accuracy: Low
        $x_1_2 = {68 04 01 00 00 68 30 ac 40 00 68 ?? ?? 40 00 ff 15 ?? 80 40 00 ff d6 68 ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Horst_L_2147608183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Horst.L"
        threat_id = "2147608183"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OpenSCManagerA" ascii //weight: 1
        $x_1_2 = "StartServiceCtrlDispatcherA" ascii //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
        $x_1_4 = "RegisterServiceCtrlHandlerA" ascii //weight: 1
        $x_1_5 = {57 57 57 57 56 53 57 ff 75 0c ff}  //weight: 1, accuracy: High
        $x_1_6 = {74 32 57 57 56 50 56 53 57 ff 75 0c ff}  //weight: 1, accuracy: High
        $x_10_7 = {6a 00 ff d6 6a 00 ff d6 6a 00 ff d6 6a 00 ff d6 6a 00 ff d6 6a 00 ff d6 6a 00 ff d6 6a 00 ff d6}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Horst_M_2147608184_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Horst.M"
        threat_id = "2147608184"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://up.medbod.com/" ascii //weight: 1
        $x_1_2 = "%s\\t%d.exe" ascii //weight: 1
        $x_1_3 = "3645FBCD-ECD2-23D0-BAC4-00DE453DEF6B" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Horst_O_2147611236_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Horst.O"
        threat_id = "2147611236"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "211"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "upseek.org" ascii //weight: 10
        $x_1_2 = "0FA728CE-55E6-A3ED-BB31-303AC1FEE01B" ascii //weight: 1
        $x_1_3 = "E0483FA8-CEA3-0296-BABC-53BEFF1746AC" ascii //weight: 1
        $x_100_4 = "CreateMutexA" ascii //weight: 100
        $x_100_5 = "InternetOpenUrlA" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Horst_V_2147712193_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Horst.V"
        threat_id = "2147712193"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 61 75 6e 63 31 7c 25 73 7c 25 64 7c 25 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 65 65 6b 2e 6f 72 67 2f 3f 72 32 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {26 72 3d 6a 63 61 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

