rule Trojan_Win32_SpawnPSProcess_SH_2147938106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpawnPSProcess.SH"
        threat_id = "2147938106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpawnPSProcess"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " & powershell.exe -windowstyle hidden" ascii //weight: 1
        $x_1_2 = " & powershell.exe -w 1" ascii //weight: 1
        $x_1_3 = " & powershell.exe -w h" ascii //weight: 1
        $x_1_4 = " & powershell.exe -nop -w hidden" ascii //weight: 1
        $x_5_5 = " bypass " ascii //weight: 5
        $x_5_6 = "-command get-process" ascii //weight: 5
        $x_10_7 = "-encodedcommand ZwBlAHQALQBwAHIAbwBjAGUAcwBzAA== &" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

