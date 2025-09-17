rule Ransom_Win64_BQTLock_BA_2147952373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BQTLock.BA!MTB"
        threat_id = "2147952373"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BQTLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Password collection attempt complete." ascii //weight: 1
        $x_1_2 = "Attempted to change icons for common file extensions." ascii //weight: 1
        $x_1_3 = "Attempting to destroy shadow copies and recovery options." ascii //weight: 1
        $x_1_4 = "vssadmin.exe delete shadows /all /quiet > NUL 2>&1" ascii //weight: 1
        $x_1_5 = "Attempting to kill security and common applications processes." ascii //weight: 1
        $x_1_6 = "A new system has been compromised and encryption has started." ascii //weight: 1
        $x_1_7 = "Encryption Complete!" ascii //weight: 1
        $x_1_8 = "All targeted files have been encrypted." ascii //weight: 1
        $x_1_9 = "schtasks /create /tn \"Microsoft\\Windows\\Maintenance\\SystemHealthCheck\" /tr " ascii //weight: 1
        $x_1_10 = "cmd.exe /C timeout /t 3 /nobreak > NUL & del /f /q " ascii //weight: 1
        $x_1_11 = "BQTLock Report" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

