rule TrojanSpy_Win32_Sybuex_B_2147624701_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Sybuex.B"
        threat_id = "2147624701"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sybuex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {77 77 77 2e 63 75 ?? ?? ?? 2e 63 6f 6d 2f [0-22] 74 61 6b [0-8] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_2 = "legend of mir" ascii //weight: 10
        $x_1_3 = "C:\\WINDOWS\\inf\\spatid.inf" ascii //weight: 1
        $x_1_4 = "svcchoster.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

