rule Ransom_Win64_FileCrypt_PGAW_2147966869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCrypt.PGAW!MTB"
        threat_id = "2147966869"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f > nul 2>&1" ascii //weight: 2
        $x_2_2 = "vssadmin delete shadows /all /quiet > nul 2>&1" ascii //weight: 2
        $x_2_3 = {64 65 6c 20 2f 66 20 2f 71 20 ?? 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 52 65 63 6f 76 65 72 79 5c 77 69 6e 72 65 2e 77 69 6d 20 3e 20 6e 75 6c 20 32 3e 26 31}  //weight: 2, accuracy: Low
        $x_2_4 = {72 64 20 2f 73 20 2f 71 20 ?? 3a 5c 52 65 63 6f 76 65 72 79 20 3e 20 6e 75 6c 20 32 3e 26 31}  //weight: 2, accuracy: Low
        $x_2_5 = {62 63 64 65 64 69 74 20 2f 65 6e 75 6d 20 3e 20 ?? 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 62 63 64 2e 74 78 74}  //weight: 2, accuracy: Low
        $x_2_6 = {73 74 61 72 74 20 2f 62 20 ?? 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 77 69 70 65 2e 62 61 74}  //weight: 2, accuracy: Low
        $x_2_7 = "killer.exe" ascii //weight: 2
        $x_2_8 = "out.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

