rule Trojan_Win32_Ripuchia_A_2147690855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ripuchia.A"
        threat_id = "2147690855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ripuchia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/GetRemoteControlCmd" ascii //weight: 2
        $x_2_2 = "/SendBinaryImageFile" ascii //weight: 2
        $x_2_3 = ": GetRemoteControlCmd() got:" wide //weight: 2
        $x_2_4 = ": ClientWebcamInfo:" wide //weight: 2
        $x_2_5 = "CreateScreenshotFromDesktop() failed:" wide //weight: 2
        $x_1_6 = "http://localhost:62338/Chipsetsync.asmx" ascii //weight: 1
        $x_1_7 = " ***==> HookBufferString:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

