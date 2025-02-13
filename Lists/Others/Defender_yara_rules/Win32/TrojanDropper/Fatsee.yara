rule TrojanDropper_Win32_Fatsee_A_2147623170_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Fatsee.A"
        threat_id = "2147623170"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Fatsee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "drivers\\tesafe.sys" ascii //weight: 1
        $x_1_2 = "\\tesafe\\Release\\server.pdb" ascii //weight: 1
        $x_1_3 = "drivers\\kvsys.sys" ascii //weight: 1
        $x_1_4 = "\\\\.\\tesafe" ascii //weight: 1
        $x_1_5 = "360Safe.exe" ascii //weight: 1
        $x_1_6 = "\\usp10.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

