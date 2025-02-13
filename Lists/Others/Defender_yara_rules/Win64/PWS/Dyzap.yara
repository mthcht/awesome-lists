rule PWS_Win64_Dyzap_A_2147687921_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/Dyzap.A"
        threat_id = "2147687921"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\DYRE\\x64\\Release\\dyrecontroller.pdb" ascii //weight: 1
        $x_1_2 = "\\\\.\\pipe\\RangisPipe" wide //weight: 1
        $x_1_3 = "/%s/%s/5/publickey/" ascii //weight: 1
        $x_1_4 = {64 00 65 00 66 00 63 00 6f 00 6e 00 66 00 69 00 67 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win64_Dyzap_B_2147687923_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/Dyzap.B"
        threat_id = "2147687923"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\DYRE\\x64\\Release\\iebattle.pdb" ascii //weight: 1
        $x_1_2 = "\\\\.\\pipe\\RangisPipe" wide //weight: 1
        $x_1_3 = "/%s/%s/14/error/%s" ascii //weight: 1
        $x_1_4 = {41 b8 00 02 00 00 c7 44 24 20 63 63 73 72 c6 44 24 24 00 e8 ?? ?? ?? ?? 8b f0 85 c0 74 66 81 fe 80 00 00 00 77 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

