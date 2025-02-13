rule TrojanSpy_Win32_Pasuom_A_2147813820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pasuom.A"
        threat_id = "2147813820"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pasuom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "uploadvalueServer" ascii //weight: 1
        $x_1_2 = "Unprotect" ascii //weight: 1
        $x_2_3 = "mymyCrypt" ascii //weight: 2
        $x_1_4 = "DataProtectionScope" ascii //weight: 1
        $x_1_5 = "\\Login Data" wide //weight: 1
        $x_1_6 = "\"encrypted_key\":\"" wide //weight: 1
        $x_3_7 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-32] 2e 00 72 00 75 00 2f 00 70 00 73 00 77 00 64 00 2e 00 70 00 68 00 70 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

