rule Trojan_Win32_Bithaw_A_2147601468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bithaw.A"
        threat_id = "2147601468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bithaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "on svchost.exe in address 0x00000890" ascii //weight: 3
        $x_1_2 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "BmsApiHook_Hook" ascii //weight: 1
        $x_1_5 = "GbPlugin\\" ascii //weight: 1
        $x_1_6 = "LdrUnloadDll" ascii //weight: 1
        $x_1_7 = "Principal_WINDOW" ascii //weight: 1
        $x_1_8 = "lE+046wVJ+kqkyAwSjZrig==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

