rule HackTool_Win32_RpivotClient_A_2147836004_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/RpivotClient.A!dha"
        threat_id = "2147836004"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RpivotClient"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PyInstaller" ascii //weight: 1
        $x_1_2 = "client.exe.manifest" ascii //weight: 1
        $x_1_3 = "b_hashlib.pyd" ascii //weight: 1
        $x_1_4 = "b_socket.pyd" ascii //weight: 1
        $x_1_5 = "b_ssl.pyd" ascii //weight: 1
        $x_1_6 = "bbz2.pyd" ascii //weight: 1
        $x_1_7 = "bselect.pyd" ascii //weight: 1
        $x_1_8 = "bunicodedata.pyd" ascii //weight: 1
        $x_1_9 = "bwin32api.pyd" ascii //weight: 1
        $x_1_10 = "bwin32evtlog.pyd" ascii //weight: 1
        $x_1_11 = "pyi-windows-manifest-filename client.exe.manifest" ascii //weight: 1
        $x_1_12 = "PYZ-00.pyz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

