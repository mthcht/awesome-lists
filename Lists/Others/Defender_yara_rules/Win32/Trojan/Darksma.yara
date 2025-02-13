rule Trojan_Win32_Darksma_C_2147576893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darksma.C"
        threat_id = "2147576893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darksma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\WINDOWS\\SYSTEM32\\shdocvs.dll" ascii //weight: 1
        $x_1_2 = "CLSID\\{00009E9F-DDD7-AA59-AA7D-AA4B7D6BE000}\\InprocServer" ascii //weight: 1
        $x_1_3 = "CLSID\\{00009E9F-DDD7-AA59-AA7D-AA4B7D6BE000}\\ProgID" ascii //weight: 1
        $x_1_4 = "CLSID\\{00009E9F-DDD7-AA59-AA7D-AA4B7D6BE000}\\TypeLib" ascii //weight: 1
        $x_1_5 = "CLSID\\{00009E9F-DDD7-AA59-AA7D-AA4B7D6BE000}\\VersionIndependentProgID" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{00009E9F-DDD7-AA59-AA7D-AA4B7D6BE000}" ascii //weight: 1
        $x_1_7 = "comcs32m.dll" ascii //weight: 1
        $x_1_8 = "comcs32u.dll" ascii //weight: 1
        $x_1_9 = "shdocvs.dll" ascii //weight: 1
        $x_1_10 = "SEARCH_CONFIG_MAIN" ascii //weight: 1
        $x_1_11 = "SEARCH_CONFIG_UPDATE" ascii //weight: 1
        $x_1_12 = "Shell Doc Object" ascii //weight: 1
        $x_1_13 = "Control Helper Class" ascii //weight: 1
        $x_1_14 = "CreateFileA" ascii //weight: 1
        $x_1_15 = "DeleteFileA" ascii //weight: 1
        $x_1_16 = "file %s, line %d" ascii //weight: 1
        $x_1_17 = "fwrite" ascii //weight: 1
        $x_1_18 = "GetCommandLineA" ascii //weight: 1
        $x_1_19 = "GetSystemDirectoryA" ascii //weight: 1
        $x_1_20 = "Out/In: %.3f" ascii //weight: 1
        $x_1_21 = "Out: %ld bytes" ascii //weight: 1
        $x_1_22 = "RegCreateKeyA" ascii //weight: 1
        $x_1_23 = "RegSetValueExA" ascii //weight: 1
        $x_1_24 = "ShellExecuteA" ascii //weight: 1
        $x_1_25 = "spoolew.exe" ascii //weight: 1
        $x_5_26 = {8d 45 fc 50 ff 75 ?? ff 75 ?? ?? ff 15 38 20 40 00 ?? ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((24 of ($x_1_*))) or
            ((1 of ($x_5_*) and 19 of ($x_1_*))) or
            (all of ($x*))
        )
}

