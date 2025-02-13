rule TrojanDropper_Win32_DelfInject_A_2147602098_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/DelfInject.A"
        threat_id = "2147602098"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "calc.exe" ascii //weight: 10
        $x_10_2 = "by shoooo" ascii //weight: 10
        $x_10_3 = "Te1ephony.exe" ascii //weight: 10
        $x_10_4 = "explorerbar" wide //weight: 10
        $x_1_5 = "TransmitFile" ascii //weight: 1
        $x_1_6 = "EnumProcesses" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_8 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

