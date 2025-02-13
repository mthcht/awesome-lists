rule TrojanSpy_Win32_Kratos_A_2147727439_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Kratos.A!bit"
        threat_id = "2147727439"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Kratos"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "api/gate.php?hwid=%s&passwords=%d&cookies=%d&forms=%d&cards=%d&desktop=%d" ascii //weight: 1
        $x_1_2 = "&wallets=%d&telegram=%d&steam=%d&filezilla=%d" ascii //weight: 1
        $x_1_3 = "XFxTY3JlZW5zaG90LmJtcA==" ascii //weight: 1
        $x_1_4 = "XFxXYWxsZXRz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

