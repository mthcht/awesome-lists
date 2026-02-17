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

rule Ransom_Win64_BQTLock_PA_2147952432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BQTLock.PA!MTB"
        threat_id = "2147952432"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BQTLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Temp\\bqt_payload.exe" ascii //weight: 5
        $x_1_2 = "Temp\\bqt_wallpaper.bmp" ascii //weight: 1
        $x_1_3 = "Temp\\bqt_screenshot" ascii //weight: 1
        $x_1_4 = "BQTLock Payload started" ascii //weight: 1
        $x_1_5 = "A new system has been infected!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_BQTLock_PA_2147952432_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BQTLock.PA!MTB"
        threat_id = "2147952432"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BQTLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "C:\\Windows\\Temp\\bqt_log.txt" ascii //weight: 6
        $x_1_2 = "BQTLock Report" ascii //weight: 1
        $x_1_3 = "files have been encrypted" ascii //weight: 1
        $x_1_4 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
        $x_1_5 = "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_6 = "Attempting to destroy shadow copies and recovery options." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_BQTLock_MG_2147954859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BQTLock.MG!MTB"
        threat_id = "2147954859"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BQTLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "INTERNAL\\REMOTE.EXE" ascii //weight: 1
        $x_1_2 = "Temp\\bqt_screenshot" ascii //weight: 1
        $x_1_3 = "A new system has been infected!" ascii //weight: 1
        $x_1_4 = "BQTLock Bot" ascii //weight: 1
        $x_1_5 = "Encryption Complete! Files" ascii //weight: 1
        $x_1_6 = "Entering persistent C2 mode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_BQTLock_AMTB_2147963201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BQTLock!AMTB"
        threat_id = "2147963201"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BQTLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "{ \"username\": \"BQTLock Bot\", \"embeds\": [{ \"title\": \"Infection Report\", \"description\": \"A new system has been infected" ascii //weight: 2
        $x_2_2 = "username\": \"BQTLock Bot\", \"embeds\": [{ \"title\": \"Encryption Complete" ascii //weight: 2
        $x_2_3 = "BQTLock Payload finished initial execution. Entering persistent C2" ascii //weight: 2
        $x_2_4 = "\\C$\\Windows\\Temp\\bqt_payload.exe" ascii //weight: 2
        $x_1_5 = "defender.exe" ascii //weight: 1
        $x_1_6 = "kaspersky.exe" ascii //weight: 1
        $x_1_7 = "mcafee.exe" ascii //weight: 1
        $x_1_8 = "sophos.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

