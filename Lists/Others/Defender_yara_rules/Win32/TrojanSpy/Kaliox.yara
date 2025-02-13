rule TrojanSpy_Win32_Kaliox_A_2147653924_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Kaliox.A"
        threat_id = "2147653924"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Kaliox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProcGo" ascii //weight: 1
        $x_1_2 = "GetFile" ascii //weight: 1
        $x_1_3 = "\\Printer\\Key.ini" ascii //weight: 1
        $x_1_4 = "/SSendNetworkInfoList.asp?HostID=" ascii //weight: 1
        $x_1_5 = "/SReadUploadFileNu.asp?HostID=" ascii //weight: 1
        $x_1_6 = "STARTSPY" ascii //weight: 1
        $x_1_7 = {3f 48 6f 73 74 49 44 3d 00 26 4f 6e 6c 69 6e 65 53 74 61 74 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

