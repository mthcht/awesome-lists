rule TrojanDropper_Win32_Tramox_A_2147706728_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tramox.A"
        threat_id = "2147706728"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tramox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":COPIARWORM" ascii //weight: 1
        $x_1_2 = "\"J:\\system\\%juego%\"" ascii //weight: 1
        $x_1_3 = "\"I:\\%moxita%\"" ascii //weight: 1
        $x_1_4 = "\"E:\\%trabajo%\"" ascii //weight: 1
        $x_1_5 = "\\Run /v wuaclt.exe /t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

