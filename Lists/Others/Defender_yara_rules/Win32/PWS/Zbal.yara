rule PWS_Win32_Zbal_A_2147688560_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zbal.A"
        threat_id = "2147688560"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[%.5d] .\\%s.%s.(%d)" ascii //weight: 1
        $x_1_2 = "Rootkit::_injectSelfToSuspended" ascii //weight: 1
        $x_1_3 = {25 42 4f 54 49 44 25 00 25 42 4f 54 4e 45 54 25}  //weight: 1, accuracy: High
        $x_1_4 = "info - __initZeusReport" ascii //weight: 1
        $x_1_5 = "sukizaebali" wide //weight: 1
        $x_1_6 = "Grabbed data from: %s" wide //weight: 1
        $x_1_7 = "webinjects.dat" wide //weight: 1
        $x_5_8 = {33 c9 52 c7 45 bc 53 00 65 00 c7 45 c0 44 00 65 00 c7 45 c4 62 00 75 00 c7 45 c8 67 00 50 00 c7 45 cc 72 00 69 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Zbal_B_2147690125_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zbal.B"
        threat_id = "2147690125"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 13 32 06 46 bb ff 00 00 00 21 c3 c1 e8 08 33 04 9f 49 75 e5}  //weight: 1, accuracy: High
        $x_1_2 = {ac 32 d0 51 6a 08 59 d1 ea 73 03 33 55 fc e2 f7 59 e2 ed}  //weight: 1, accuracy: High
        $x_1_3 = "starayamoskva" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Zbal_C_2147716910_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zbal.C"
        threat_id = "2147716910"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 6f 74 69 c7 85 ?? ?? ?? ?? 64 3d 25 73 c7 85 ?? ?? ?? ?? 0d 0a 62 6f c7 85 ?? ?? ?? ?? 74 6e 65 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 f8 50 c7 45 f8 6f 75 74 2e c7 45 fc 64 61 74 00 68}  //weight: 1, accuracy: High
        $x_1_3 = {2a 00 2e 00 73 00 6f 00 6c 00 00 00 66 00 6c 00 61 00 73 00 68 00 70 00 6c 00 61 00 79 00 65 00 72 00 2e 00 63 00 61 00 62 00 00 00 4d 00 61 00 63 00 72 00 6f 00 6d 00 65 00 64 00 69 00 61 00 5c 00 46 00 6c 00 61 00 73 00 68 00 20 00 50 00 6c 00 61 00 79 00 65 00 72 00}  //weight: 1, accuracy: High
        $x_1_4 = "debug\\full\\%02d_%02d_%02d_%02d__%04d.txt" wide //weight: 1
        $x_1_5 = {77 00 61 00 6c 00 6c 00 65 00 74 00 2e 00 64 00 61 00 74 00 00 00 00 00 65 00 6c 00 65 00 63 00 74 00 72 00 75 00 6d 00 2e 00 64 00 61 00 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

