rule TrojanDropper_Win32_Netsky_D_2147582440_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Netsky.D"
        threat_id = "2147582440"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Netsky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "U'l't'i'm'a't'i'v'e 'E'n'c'r'y'p't'e'd 'W'o'r'm'D'r'o'p'p'e'r' 'b'y 'S'k'y'N'e't'.'C'Z' 'C'o'r'p" ascii //weight: 6
        $x_6_2 = "'D'r'o'p'p'e'd'S'k'y'N'e't'" ascii //weight: 6
        $x_6_3 = "'S'k'y'N'e't'F'i'g'h't's'B'a'c'k" ascii //weight: 6
        $x_6_4 = "D'r'o'p'p'e'r' 'b'y 'S'k'y'N'e't'.'C'Z' 'C'o'r'p*'" ascii //weight: 6
        $x_3_5 = "FVProtect.exe" ascii //weight: 3
        $x_3_6 = "userconfig9x.dll" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_6_*) and 2 of ($x_3_*))) or
            ((4 of ($x_6_*))) or
            (all of ($x*))
        )
}

