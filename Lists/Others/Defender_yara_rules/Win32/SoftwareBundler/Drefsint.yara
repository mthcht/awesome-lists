rule SoftwareBundler_Win32_Drefsint_223265_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Drefsint"
        threat_id = "223265"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Drefsint"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 4d 4d 2d 6c 69 61 6f 39 37 32 38 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 64 72 65 61 6d 5c 31 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = ") do rd /s/q \"%appdata%\\%%a\" >nul 2>nul" ascii //weight: 1
        $x_1_4 = ") do reg delete %%a\\%%b /va /f >nul 2>nul" ascii //weight: 1
        $x_1_5 = {5c 55 6e 69 6e 73 74 61 6c 6c 5c 00 4e 56 49 44 49 41 00 57 69 6e 64 6f 77 73 00 4d 69 63 72 6f 73 6f 66 74}  //weight: 1, accuracy: High
        $x_1_6 = "180.153.147.73/fsintf/c9f2549fce18f4dc4ae13d6a6527d9c4e/" ascii //weight: 1
        $x_1_7 = "cnrdn.com/rd.htm?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

