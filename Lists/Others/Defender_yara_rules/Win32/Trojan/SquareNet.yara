rule Trojan_Win32_SquareNet_R_2147727749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SquareNet.R"
        threat_id = "2147727749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SquareNet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "svcvmx.exe" wide //weight: 4
        $x_3_2 = "ct=%1&dataup=%2&cpx=%3&svcvmx=%4&qdcomsvc=%5&szpsrv=%6&splsrv=%7" ascii //weight: 3
        $x_3_3 = "E:\\svcvmx\\build\\Release\\svcvmx2.exe.pdb" ascii //weight: 3
        $x_2_4 = "http://www.gpt9.com/api/qzmd" ascii //weight: 2
        $x_2_5 = "http://www.liuliangshu.com/clienimproxy8" ascii //weight: 2
        $x_1_6 = "Clone() is not implemented yet." ascii //weight: 1
        $x_1_7 = "FortiClientVirusCleaner.exe" ascii //weight: 1
        $x_1_8 = "Norman_Malware_Cleaner.exe" ascii //weight: 1
        $x_1_9 = "Sophos UI.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SquareNet_P_2147727750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SquareNet.P"
        threat_id = "2147727750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SquareNet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\dp-3000\\ds.vbp" wide //weight: 1
        $x_1_2 = "\\dataup.ini" wide //weight: 1
        $x_1_3 = "http://www.58hex.com/databack.php" wide //weight: 1
        $x_1_4 = "http://www.jeegtube.com/databack.php" wide //weight: 1
        $x_1_5 = "dataup.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_SquareNet_Q_2147727751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SquareNet.Q"
        threat_id = "2147727751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SquareNet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\chromium\\src\\base\\pickle.cc" ascii //weight: 1
        $x_1_2 = "{ED6901A1-2E80-4FBA-AAD5-84638FC3F382}" ascii //weight: 1
        $x_1_3 = "{ED6901A1-2E80-4FBA-AAD5-84638FC3F382}" wide //weight: 1
        $x_3_4 = ":\\cef_2883\\chromium_git\\chromium\\src\\out\\Release_GN_x86\\vmxclient.exe.pdb" ascii //weight: 3
        $x_3_5 = ":\\cef_2526\\download\\chromium\\src\\out\\Release\\winltc.exe.pdb" ascii //weight: 3
        $x_2_6 = "winltc.exe" ascii //weight: 2
        $x_2_7 = "vmxclient.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

