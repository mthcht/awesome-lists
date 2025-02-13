rule TrojanSpy_Win32_Fankoob_A_2147657630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Fankoob.A"
        threat_id = "2147657630"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Fankoob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "305"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "2F1701101010060109" wide //weight: 100
        $x_100_2 = "7A808D7683DF76D15AEA28FD040B14F7020F44D326F1" wide //weight: 100
        $x_100_3 = "8A907C8491A9A1A47687829F66AD76AE7DBC4C0E14E136" wide //weight: 100
        $x_10_4 = "94948C8E9466FF101A58BB45D629E12124332AE" wide //weight: 10
        $x_5_5 = "1E1812F539CF3EEB3BC266C754D531D42DFE1CE42419FB1E" wide //weight: 5
        $x_5_6 = "E735D53DFC22EE15E22AE1221DE02AE936C74FDF57AE64" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 1 of ($x_5_*))) or
            ((3 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

