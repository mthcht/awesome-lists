rule Ransom_Win32_Distrack_A_2147746205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Distrack.A!MSR"
        threat_id = "2147746205"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Distrack"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "zeroclear.exe" wide //weight: 5
        $x_5_2 = "elrawdsk.sys\"" wide //weight: 5
        $x_1_3 = "/u /c sc create soydsk type= kernel start= demand binPath= \"" wide //weight: 1
        $x_1_4 = "/u /c sc start soydsk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

