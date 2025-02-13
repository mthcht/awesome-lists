rule Trojan_Win32_ProcessInjector_A_2147769829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessInjector.A"
        threat_id = "2147769829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessInjector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[*] Running the target executable" ascii //weight: 1
        $x_1_2 = "[*] Process created in suspended state" ascii //weight: 1
        $x_1_3 = "[*] Memory unmapped from child process!" ascii //weight: 1
        $x_1_4 = "[*] Allocating RWX memory in child process" ascii //weight: 1
        $x_1_5 = "[*] Writing executable image into child process" ascii //weight: 1
        $x_1_6 = "[*] Setting the context of the child process's primary thread" ascii //weight: 1
        $x_1_7 = "[*] Thread resumed" ascii //weight: 1
        $x_1_8 = "NtSetContextThread" ascii //weight: 1
        $x_1_9 = "NtWriteVirtualMemory" ascii //weight: 1
        $x_1_10 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_11 = "NtResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_ProcessInjector_B_2147769835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessInjector.B"
        threat_id = "2147769835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessInjector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\fin7_injectDLL-shim_step19\\Release\\step19.pdb" ascii //weight: 1
        $x_1_2 = "ZwMapViewOfSection" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "CreateRemoteThread" ascii //weight: 1
        $x_1_5 = "MapViewOfFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

