rule TrojanSpy_Win32_Zbot_MA_2147815339_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Zbot.MA!MTB"
        threat_id = "2147815339"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b3 50 fc 44 8b 85 ?? ?? ?? ?? ed 3c 3a 4f ad 33 99 ?? ?? ?? ?? 0c 00 aa 00 60 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

