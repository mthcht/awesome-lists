rule TrojanDropper_Win32_Sefnit_L_2147686556_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sefnit.L"
        threat_id = "2147686556"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%%\\dfrg" ascii //weight: 1
        $x_1_2 = "\\svc.exe\" -i" ascii //weight: 1
        $x_1_3 = "\\runner.exe" ascii //weight: 1
        $x_1_4 = "%%\\__test" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

