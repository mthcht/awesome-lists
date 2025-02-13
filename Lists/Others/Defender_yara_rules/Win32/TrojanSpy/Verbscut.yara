rule TrojanSpy_Win32_Verbscut_A_2147682225_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Verbscut.A"
        threat_id = "2147682225"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Verbscut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" ascii //weight: 2
        $x_3_2 = "TVrBscThread" ascii //weight: 3
        $x_3_3 = "uIE9_Decode" ascii //weight: 3
        $x_5_4 = "Senha .: %s" ascii //weight: 5
        $x_5_5 = "URL ...: %s" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

