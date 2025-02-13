rule Trojan_Win32_Harnbrush_A_2147623072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Harnbrush.A"
        threat_id = "2147623072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnbrush"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ftp://brushy:brushy" ascii //weight: 4
        $x_4_2 = ".mailhunt.cn/brush" ascii //weight: 4
        $x_4_3 = {2e 69 6e 69 00 00 00 47 65 74 50 72 69 76 61 74 65 50 72 6f 66 69 6c 65 49 6e 74}  //weight: 4, accuracy: High
        $x_2_4 = "CreateProcess---IEXPLORE.EXE" ascii //weight: 2
        $x_2_5 = "moni.dll_InitTskHead" ascii //weight: 2
        $x_2_6 = "SaveIEProcessID" ascii //weight: 2
        $x_1_7 = "BrowserFrameGripperClass" ascii //weight: 1
        $x_1_8 = "SendMsg At 0_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

