rule TrojanSpy_Win32_Seryce_A_2147652972_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Seryce.A"
        threat_id = "2147652972"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Seryce"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {99 b9 e8 03 00 00 f7 f9 42 52 ff d3 46 83 fe 08}  //weight: 4, accuracy: High
        $x_2_2 = {6a 06 6a 01 6a 02 ff 15 ?? ?? ?? 00 8b f0 83 fe ff 74 db b8 02 00 00 00 6a 50}  //weight: 2, accuracy: Low
        $x_1_3 = "_abroad" ascii //weight: 1
        $x_1_4 = "_china" ascii //weight: 1
        $x_1_5 = "!win7" ascii //weight: 1
        $x_1_6 = "gotowin.EncryptDecrypt.Simple" ascii //weight: 1
        $x_1_7 = "HostID=%s&Version=%s&OS=%s&ip=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

