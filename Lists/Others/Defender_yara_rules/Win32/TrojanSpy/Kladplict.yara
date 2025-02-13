rule TrojanSpy_Win32_Kladplict_A_2147718054_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Kladplict.A"
        threat_id = "2147718054"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Kladplict"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 57 c0 0f 11 45 ea c7 45 fa 00 00 00 00 6a 0c 66 c7 45 fe 00 00 89 45 f0 89 45 fc 8d 45 e8 6a 02 50 c7 45 e8 01 00 06 00 c7 45 ec 00 01 00 00 c7 45 f4 01 00 02 00 c7 45 f8 00 01 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = "[clipboard begin]" ascii //weight: 1
        $x_1_3 = "kl.dat" wide //weight: 1
        $x_1_4 = "Main Returned." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

