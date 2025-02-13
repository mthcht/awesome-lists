rule TrojanSpy_Win32_Gwghost_M_2147602886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gwghost.M"
        threat_id = "2147602886"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gwghost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\GWGMTA.LOG" ascii //weight: 1
        $x_1_2 = "c:\\recycled\\" ascii //weight: 1
        $x_1_3 = "c:\\recycler\\" ascii //weight: 1
        $x_5_4 = {8b f0 6a 20 56 6a 00 6a 00 6a 00 68 00 04 00 00 e8 ?? ?? ?? ?? 48 03 f0 c6 06 20 46 6a 20 56 6a 00 6a 00 6a 00 68 00 04 00 00 e8 ?? ?? ?? ?? 48 03 f0 ba ?? ?? ?? ?? 8b c6 e8 ?? ?? ?? ?? 8b f0 6a 00 8d 55 f4 52 8d 85 ?? ?? ?? ?? 2b f0 56 50 53 e8 ?? ?? ?? ?? 6a 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

