rule Backdoor_Win32_Senmilox_A_2147650789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Senmilox.A"
        threat_id = "2147650789"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Senmilox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Milosz Programs" wide //weight: 1
        $x_1_2 = "ConfigurazioniUACex.bat" wide //weight: 1
        $x_1_3 = "\\a1cx3.dll" wide //weight: 1
        $x_1_4 = "\\msrs32.exe" wide //weight: 1
        $x_1_5 = "shutdown -s -t 5" wide //weight: 1
        $x_1_6 = "RunDll32 User32.Dll,SwapMouseButton" wide //weight: 1
        $x_1_7 = "EnableLUA /t REG_DWORD /d 0" wide //weight: 1
        $x_1_8 = "del Configurazionisxxxs.bat" wide //weight: 1
        $x_1_9 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

