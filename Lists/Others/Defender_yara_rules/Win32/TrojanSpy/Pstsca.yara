rule TrojanSpy_Win32_Pstsca_A_2147708315_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pstsca.A"
        threat_id = "2147708315"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pstsca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill.exe /f /t /im outlook.exe" ascii //weight: 1
        $x_1_2 = {66 83 f8 70 75 53 66 8b 4e 04 e8 bc ff ff ff 66 83 f8 73 75 44 66 8b 4e 06 e8 ad ff ff ff 66 83 f8 74 75 35 66 39 56 08 75 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

