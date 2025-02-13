rule Ransom_Win32_Shrug_A_2147748561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Shrug.A!MSR"
        threat_id = "2147748561"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Shrug"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C choice /C Y /N /D Y /T 1 & Del" wide //weight: 1
        $x_1_2 = "/C Icacls . /grant Everyone:F /T /C /Q" wide //weight: 1
        $x_1_3 = "FilesToHarm" ascii //weight: 1
        $x_2_4 = ".SHRUG2" wide //weight: 2
        $x_2_5 = "ShrugDecryptor" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

