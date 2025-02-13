rule TrojanSpy_Win32_Potian_A_2147620196_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Potian.A"
        threat_id = "2147620196"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Potian"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hook.dll" ascii //weight: 1
        $x_1_2 = "starhook" ascii //weight: 1
        $x_1_3 = "219.153.51.47" ascii //weight: 1
        $x_1_4 = {00 00 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 63 68 69 6e 61 5f 6c 6f 67 69 6e 2e 6d 70 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

