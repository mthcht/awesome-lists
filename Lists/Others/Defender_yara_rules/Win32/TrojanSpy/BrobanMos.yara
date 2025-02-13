rule TrojanSpy_Win32_BrobanMos_A_2147695243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/BrobanMos.A"
        threat_id = "2147695243"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanMos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "contador2a" ascii //weight: 1
        $x_1_2 = "\\loaderFirefox.vbp" wide //weight: 1
        $x_1_3 = "IsXPILoaded" ascii //weight: 1
        $x_1_4 = "resources/firefoxext/data/background.jsPK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

