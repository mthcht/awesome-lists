rule TrojanSpy_Win32_Zaiyi_A_2147712278_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Zaiyi.A!dha"
        threat_id = "2147712278"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Zaiyi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "heizai2011" ascii //weight: 1
        $x_1_2 = "svcbr2345" ascii //weight: 1
        $x_1_3 = "t1120" ascii //weight: 1
        $x_1_4 = "creat random filename!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

