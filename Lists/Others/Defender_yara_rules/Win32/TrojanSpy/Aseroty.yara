rule TrojanSpy_Win32_Aseroty_A_2147822784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Aseroty.A"
        threat_id = "2147822784"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Aseroty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sc.exe create" wide //weight: 1
        $x_1_2 = "sc create" wide //weight: 1
        $x_20_3 = {62 00 69 00 6e 00 50 00 61 00 74 00 68 00 3d 00 [0-240] 61 00 73 00 77 00 61 00 72 00 70 00 6f 00 74 00 2e 00 73 00 79 00 73 00}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

