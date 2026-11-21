rule Trojan_Win32_SheetRAT_2147982571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SheetRAT!atmn"
        threat_id = "2147982571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SheetRAT"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "schtasks" wide //weight: 5
        $x_5_2 = "/create /f" wide //weight: 5
        $x_7_3 = "Microsoft\\MachineCore" wide //weight: 7
        $x_10_4 = "C:\\Windows\\xdwdWeb\\MalwareDef.exe" wide //weight: 10
        $x_7_5 = "/sc minute" wide //weight: 7
        $x_5_6 = "/mo 30" wide //weight: 5
        $x_5_7 = "/RL HIGHEST & exit" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SheetRAT_2147982571_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SheetRAT!atmn"
        threat_id = "2147982571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SheetRAT"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "schtasks" wide //weight: 5
        $x_5_2 = "/create /f" wide //weight: 5
        $x_7_3 = "Microsoft\\Windows\\WAppCrashNvTew" wide //weight: 7
        $x_10_4 = "C:\\Windows\\xdwdSystem32\\Defender.exe" wide //weight: 10
        $x_7_5 = "/sc minute" wide //weight: 7
        $x_5_6 = "/mo 1" wide //weight: 5
        $x_5_7 = "/RL HIGHEST & exit" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

