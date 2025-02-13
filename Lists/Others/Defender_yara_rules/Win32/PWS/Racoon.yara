rule PWS_Win32_Racoon_PAA_2147808974_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Racoon.PAA!MTB"
        threat_id = "2147808974"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Racoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-executionpolicy bypass -command .\\racoon.ps1" wide //weight: 10
        $x_1_2 = "web/upload.php" ascii //weight: 1
        $x_1_3 = "/c \"--defaults-torrc" wide //weight: 1
        $x_1_4 = "adv firewall set opmode mode disable" wide //weight: 1
        $x_1_5 = "(Get-WmiObject Win32_OperatingSystem).SystemDrive" ascii //weight: 1
        $x_1_6 = "cmd /c 'whoami.exe && systeminfo.exe && ipconfig.exe && netstat.exe'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Racoon_AD_2147812187_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Racoon.AD!MTB"
        threat_id = "2147812187"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Racoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinHttpSetOption" ascii //weight: 1
        $x_1_2 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_3 = "DecodePointer" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "CreateProcessWithTokenW" ascii //weight: 1
        $x_1_6 = "WinHttpQueryDataAvailable" ascii //weight: 1
        $x_1_7 = "wild scan" ascii //weight: 1
        $x_1_8 = "GetLastActivePopup" ascii //weight: 1
        $x_1_9 = "CryptUnprotectData" ascii //weight: 1
        $x_1_10 = "Process32NextW" ascii //weight: 1
        $x_1_11 = "CreateCompatibleDC" ascii //weight: 1
        $x_1_12 = "CreateProcessA" ascii //weight: 1
        $x_1_13 = "GlobalMemoryStatusEx" ascii //weight: 1
        $x_1_14 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_15 = "CreateDirectoryTransactedA" ascii //weight: 1
        $x_1_16 = "AppPolicyGetProcessTerminationMethod" ascii //weight: 1
        $x_1_17 = "network reset" ascii //weight: 1
        $x_1_18 = "GetSystemPowerStatus" ascii //weight: 1
        $x_1_19 = "WinHttpReadData" ascii //weight: 1
        $x_1_20 = "BCryptDestroyKey" ascii //weight: 1
        $x_1_21 = "CreateTransaction" ascii //weight: 1
        $x_1_22 = "CommitTransaction" ascii //weight: 1
        $x_1_23 = "WinHttpSendRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

