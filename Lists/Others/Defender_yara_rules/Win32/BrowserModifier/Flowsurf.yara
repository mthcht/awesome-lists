rule BrowserModifier_Win32_Flowsurf_228800_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Flowsurf"
        threat_id = "228800"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Flowsurf"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a 00 44 00 44 00 4c 00 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "7DCD6A34-0FA8-4EC9-B20D-263537FD54C9" ascii //weight: 1
        $x_1_3 = "376DC5FA-503F-41AD-8ECD-EA31C3EA63AD" ascii //weight: 1
        $x_1_4 = {48 83 c9 ff b8 34 00 00 00 66 89 84 24 ?? 01 00 00 b8 6a 00 00 00 ba 36 00 00 00 66 89 84 24 ?? 01 00 00 66 89 94 24 ?? 01 00 00 ba 69 00 00 00 66 89 94 24 ?? 01 00 00 66 89 94 24 ?? 01 00 00 b8 2e 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Flowsurf_228800_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Flowsurf"
        threat_id = "228800"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Flowsurf"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "D394F651-3089-454B-900D-858F2AA33413" ascii //weight: 1
        $x_1_2 = "73114C0D-9CAA-4051-BF62-BAD3FFD9DB50" ascii //weight: 1
        $x_1_3 = "7DCD6A34-0FA8-4EC9-B20D-263537FD54C9" ascii //weight: 1
        $x_1_4 = "376DC5FA-503F-41AD-8ECD-EA31C3EA63AD" ascii //weight: 1
        $x_3_5 = {83 c4 0c 8d 84 24 ?? 02 00 00 50 8b c8 51 c6 84 24 ?? 02 00 00 62 88 9c 24 ?? 02 00 00 c6 84 24 ?? 02 00 00 63 c6 84 24 ?? 02 00 00 79 c6 84 24 ?? 02 00 00 63 c6 84 24 ?? 02 00 00 70 c6 84 24 ?? 02 00 00 61 c6 84 24 ?? 02 00 00 4a 88 9c 24 ?? 02 00 00 c6 84 24 ?? 02 00 00 73 c6 84 24 ?? 02 00 00 42 c6 84 24 ?? 02 00 00 4c c6 84 24 ?? 02 00 00 73 c6 84 24 ?? 02 00 00 55 ff d6}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

