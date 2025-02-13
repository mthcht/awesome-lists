rule TrojanSpy_Win32_OnLineGames_2147605885_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/OnLineGames"
        threat_id = "2147605885"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c7 85 14 fe ff ff 5d e4 36 57 c6 85 1c fe ff ff 01 c7 85 20 fe ff ff 68 d8 1a ef}  //weight: 10, accuracy: High
        $x_1_2 = "_!QGUA_MAHUA!_" ascii //weight: 1
        $x_1_3 = "QGApp" ascii //weight: 1
        $x_1_4 = "Software\\Tencent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_OnLineGames_2147605885_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/OnLineGames"
        threat_id = "2147605885"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 4c 4c 2e 64 6c 6c 00 41 6c 70 68 61 42 6c 65 6e 64 00 44 6c 6c}  //weight: 10, accuracy: High
        $x_10_2 = "TSSafeEdit.dat" ascii //weight: 10
        $x_1_3 = "MPSockLib" ascii //weight: 1
        $x_1_4 = "MPGoodStatus" ascii //weight: 1
        $x_1_5 = {47 45 54 00 52 65 66 65 72 65 72 00 71 64 5f 62 61 6c 61 6e 63 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

