rule Backdoor_Win64_TurlaCarbon_2147849677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/TurlaCarbon"
        threat_id = "2147849677"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "TurlaCarbon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYSTEM\\CurrentControlSet\\services\\WinResSvc\\Parameters" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_1_3 = "Set victim UUID to" ascii //weight: 1
        $x_1_4 = "Set up peer to peer" ascii //weight: 1
        $x_1_5 = "Saved task from peer" ascii //weight: 1
        $x_1_6 = "Saved task from C2 server" ascii //weight: 1
        $x_1_7 = "Saving payload to" ascii //weight: 1
        $x_1_8 = "/javascript/view.php" ascii //weight: 1
        $x_1_9 = "[WARN-INJ] Reinjecting due to error, see error log" ascii //weight: 1
        $x_1_10 = "[WARN-INJ] GetProcessVectorsHandlePIDsPPIDs failed for process " ascii //weight: 1
        $x_1_11 = "[WARN-TASK] Unable to build task from line, error: " ascii //weight: 1
        $x_1_12 = "[TASK] Task successfully built" ascii //weight: 1
        $x_1_13 = "[TASK] Task config:" ascii //weight: 1
        $x_1_14 = "[TASK] Releasing mutex, sleeping..." ascii //weight: 1
        $x_1_15 = "[TASK] Recieved task line: " ascii //weight: 1
        $x_1_16 = "[TASK] Payload filepath: " ascii //weight: 1
        $x_1_17 = "[TASK] Orchestrator task file size: " ascii //weight: 1
        $x_1_18 = "[TASK] Comms lib inactive, sleeping" ascii //weight: 1
        $x_1_19 = "[TASK] Attempting to get ownership of mutex: " ascii //weight: 1
        $x_1_20 = "[ORCH] Send file path: " ascii //weight: 1
        $x_1_21 = "[ORCH] Config contents:" ascii //weight: 1
        $x_1_22 = "[MTX] Successfully created mutexes" ascii //weight: 1
        $x_1_23 = "[MAIN] Starting injection loop" ascii //weight: 1
        $x_1_24 = "[INJ] Attempting to inject into " ascii //weight: 1
        $x_1_25 = "[ERROR-TASK] Tasking ReadTaskFile encountered error reading task file " ascii //weight: 1
        $x_1_26 = "[ERROR-TASK] CreateProcessA failed. GetLastError: " ascii //weight: 1
        $x_1_27 = "[ERROR-INJ] targetProcesses is empty after attempting to build vector." ascii //weight: 1
        $x_1_28 = "[ERROR-INJ] targetProcList is empty after GetConfigValue call." ascii //weight: 1
        $x_1_29 = "[ERROR-INJ] WriteProcessMemory failed. GetLastError: " ascii //weight: 1
        $x_1_30 = "[ERROR-INJ] Unable to locate DLL to inject at path: " ascii //weight: 1
        $x_1_31 = "[ERROR-INJ] Snapshot empty or issue with Process32First. GetLastError: " ascii //weight: 1
        $x_1_32 = "[ERROR-INJ] PerformInjection failed for process " ascii //weight: 1
        $x_1_33 = "[ERROR-INJ] InjectionMain failed with error code: " ascii //weight: 1
        $x_1_34 = "[ERROR-INJ] CreateToolhelp32Snapshot failed. GetLastError: " ascii //weight: 1
        $x_1_35 = "[ERROR-INJ] AdjustTokenPrivileges failed. ReturnValue: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_TurlaCarbon_O_2147849700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/TurlaCarbon.O"
        threat_id = "2147849700"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "TurlaCarbon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.54" ascii //weight: 1
        $x_1_2 = "Global\\DriveEncryptionStd" wide //weight: 1
        $x_1_3 = "Global\\DriveHealthOverwatch" wide //weight: 1
        $x_1_4 = "Global\\Microsoft.Telemetry.Configuration" wide //weight: 1
        $x_1_5 = "workdict.xml" ascii //weight: 1
        $x_1_6 = "CW_LOCAL" ascii //weight: 1
        $x_1_7 = "CW_INET" ascii //weight: 1
        $x_1_8 = "[P2P HANDLER]" ascii //weight: 1
        $x_1_9 = {2f 6a 61 76 61 73 63 72 69 70 74 2f 76 69 65 77 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_10 = {74 72 61 6e 73 5f 74 69 6d 65 6d 61 78 00}  //weight: 1, accuracy: High
        $x_1_11 = {73 79 73 74 65 6d 5f 70 69 70 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

