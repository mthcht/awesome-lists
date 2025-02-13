rule TrojanSpy_Win32_Platcyber_A_2147639648_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Platcyber.A"
        threat_id = "2147639648"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Platcyber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PasswordEditKeyPress" ascii //weight: 2
        $x_2_2 = "&type=secret&data=" ascii //weight: 2
        $x_1_3 = "&type=pubkeys&data=" ascii //weight: 1
        $x_2_4 = "i8bh1PrJifrM4q" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

