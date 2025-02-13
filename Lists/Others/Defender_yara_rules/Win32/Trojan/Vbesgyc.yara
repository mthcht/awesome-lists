rule Trojan_Win32_Vbesgyc_A_2147685054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vbesgyc.A"
        threat_id = "2147685054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbesgyc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NT Kernel & System" ascii //weight: 1
        $x_1_2 = "C:\\Documents and Settings\\Administrator\\Application Data\\cftmon.exe" ascii //weight: 1
        $x_1_3 = {5c 00 6d 00 4d 00 65 00 6c 00 74 00 2e 00 62 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "ADD HKLM\\SOFTWARE\\Microsoft\\Security Center /V UACDisableNotify /t REG_DWORD /d 0 /f" wide //weight: 1
        $x_1_6 = "ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /V EnableLUA /t REG_DWORD /d 0 /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

