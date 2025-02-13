rule Trojan_Win32_TurlaCarbon_2147849698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbon"
        threat_id = "2147849698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 c0 f8 48 83 f8 1f 0f 87 ?? ?? ?? ?? 48 8b cb e8 ?? ?? ?? ?? bf 08 00 00 00 48 89 75 00 48 bb 64 65 6c 5f 74 61 73 6b}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 04 00 00 00 48 89 75 00 48 8d 54 24 50 48 89 5d f8 48 8d 4d a8 c7 45 e8 6e 61 6d 65 44 88 65 ec e8}  //weight: 1, accuracy: High
        $x_1_3 = "Uploading: " ascii //weight: 1
        $x_1_4 = "Deleting: " ascii //weight: 1
        $x_1_5 = "Downloading: " ascii //weight: 1
        $x_1_6 = "List files for: " ascii //weight: 1
        $x_1_7 = {7b 22 55 55 49 44 22 3a 22 00}  //weight: 1, accuracy: High
        $x_1_8 = {22 2c 20 22 64 61 74 61 22 3a 22 00}  //weight: 1, accuracy: High
        $x_1_9 = {22 2c 20 22 74 79 70 65 22 3a 22 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TurlaCarbon_A_2147849722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A"
        threat_id = "2147849722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbon"
        severity = "Critical"
        info = "TurlaCarbon: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[CTRL+BREAK PROCESSING]" ascii //weight: 1
        $x_1_2 = "[IME JUNJA MODE]" ascii //weight: 1
        $x_1_3 = "Failed to created process with duplicated token. Error code: " ascii //weight: 1
        $x_1_4 = "Set hooks" ascii //weight: 1
        $x_1_5 = "Error getting temp path:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TurlaCarbon_A_2147849722_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A"
        threat_id = "2147849722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbon"
        severity = "Critical"
        info = "TurlaCarbon: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 c0 f8 48 83 f8 1f 0f 87 ?? ?? ?? ?? 48 8b cb e8 ?? ?? ?? ?? bf 08 00 00 00 48 89 75 00 48 bb 64 65 6c 5f 74 61 73 6b}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 04 00 00 00 48 89 75 00 48 8d 54 24 50 48 89 5d f8 48 8d 4d a8 c7 45 e8 6e 61 6d 65 44 88 65 ec e8}  //weight: 1, accuracy: High
        $x_1_3 = "Uploading: " ascii //weight: 1
        $x_1_4 = "Deleting: " ascii //weight: 1
        $x_1_5 = "Downloading: " ascii //weight: 1
        $x_1_6 = "List files for: " ascii //weight: 1
        $x_1_7 = {7b 22 55 55 49 44 22 3a 22 00}  //weight: 1, accuracy: High
        $x_1_8 = {22 2c 20 22 64 61 74 61 22 3a 22 00}  //weight: 1, accuracy: High
        $x_1_9 = {22 2c 20 22 74 79 70 65 22 3a 22 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TurlaCarbon_A_2147849722_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A"
        threat_id = "2147849722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbon"
        severity = "Critical"
        info = "TurlaCarbon: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinResSvc" ascii //weight: 1
        $x_1_2 = "C:\\Program Files\\Windows NT\\MSSVCCFG.dll" ascii //weight: 1
        $x_1_3 = "Failed to set up service. Error code: %d" ascii //weight: 1
        $x_1_4 = "VirtualQuery failed for %d bytes at address %p" ascii //weight: 1
        $x_1_5 = "VirtualProtect failed with code 0x%x" ascii //weight: 1
        $x_1_6 = "%p not found?!?!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TurlaCarbon_A_2147849722_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A"
        threat_id = "2147849722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbon"
        severity = "Critical"
        info = "TurlaCarbon: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pipe\\commctrldev" wide //weight: 1
        $x_1_2 = "pipe\\commsecdev" wide //weight: 1
        $x_1_3 = "installer.exe" ascii //weight: 1
        $x_1_4 = "Could not delete {}\\{}.sys" ascii //weight: 1
        $x_2_5 = "installer.pdb" ascii //weight: 2
        $x_2_6 = "/PUB/home.html" wide //weight: 2
        $x_2_7 = "cheapinfomedical99.net" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TurlaCarbon_A_2147849722_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A"
        threat_id = "2147849722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbon"
        severity = "Critical"
        info = "TurlaCarbon: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "N8CryptoPP12CAST128_InfoE" ascii //weight: 1
        $x_1_2 = "%p not found?!?!" ascii //weight: 1
        $x_1_3 = "T%p %d V=%0X H=%p %s" ascii //weight: 1
        $x_1_4 = "[TASK] Outputting to send file:" ascii //weight: 1
        $x_1_5 = "[TASK] Comms lib active, performing tasking checks" ascii //weight: 1
        $x_1_6 = "[TASK] Attempting to get ownership of mutex:" ascii //weight: 1
        $x_1_7 = "C:\\Program Files\\Windows NT\\history.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TurlaCarbon_A_2147849722_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A"
        threat_id = "2147849722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbon"
        severity = "Critical"
        info = "TurlaCarbon: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Failed to parse beacon response. Error code:" ascii //weight: 1
        $x_1_2 = "Heartbeat failed. Error code:" ascii //weight: 1
        $x_1_3 = "Truncated pipe server log file." ascii //weight: 1
        $x_1_4 = "Successfully uploaded C2 log file." ascii //weight: 1
        $x_1_5 = "Downloaded payload:" ascii //weight: 1
        $x_1_6 = "Discovered computer name:" ascii //weight: 1
        $x_1_7 = "Set implant ID to" ascii //weight: 1
        $x_1_8 = "Received empty intruction. Will forward to executor client." ascii //weight: 1
        $x_1_9 = "Failed to execute task. Error code:" ascii //weight: 1
        $x_1_10 = "checkmateNASA" ascii //weight: 1
        $x_1_11 = "[ERROR] Failed to wait for mutex. Error code: " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_TurlaCarbon_A_2147849722_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A"
        threat_id = "2147849722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbon"
        severity = "Critical"
        info = "TurlaCarbon: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
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

rule Trojan_Win32_TurlaCarbon_A_2147849722_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A"
        threat_id = "2147849722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbon"
        severity = "Critical"
        info = "TurlaCarbon: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36" wide //weight: 1
        $x_1_2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0" wide //weight: 1
        $x_1_3 = "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko" wide //weight: 1
        $x_2_4 = "C:\\Windows\\$NtUninstallQ608317$" wide //weight: 2
        $x_2_5 = "Set implant ID to " ascii //weight: 2
        $x_2_6 = "Shell Command: " ascii //weight: 2
        $x_2_7 = "Run as user: " ascii //weight: 2
        $x_2_8 = "Upload file" ascii //weight: 2
        $x_1_9 = "Global\\WinBaseSvcDBLock" wide //weight: 1
        $x_1_10 = "Global\\WindowsCommCtrlDB" wide //weight: 1
        $x_1_11 = "/IMAGES/3/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 5 of ($x_1_*))) or
            ((5 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TurlaCarbon_A_2147849722_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A"
        threat_id = "2147849722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbon"
        severity = "Critical"
        info = "TurlaCarbon: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
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

