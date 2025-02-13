rule TrojanSpy_Win32_Haxor_A_2147612387_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Haxor.A"
        threat_id = "2147612387"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Haxor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "IE(AL(\"%s\",4),\"AL(\\\"%0:s\\\",3)\"" ascii //weight: 10
        $x_10_2 = "JumpID(\"\",\"%s\")" ascii //weight: 10
        $x_10_3 = "h4x0rkill" ascii //weight: 10
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "Heap32ListFirst" ascii //weight: 1
        $x_1_6 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_7 = "ThreadGeral" ascii //weight: 1
        $x_1_8 = "ThreadDeleta" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

