rule TrojanDropper_Win32_Protmin_A_2147627840_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Protmin.A"
        threat_id = "2147627840"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Protmin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SystemRoot\\System32\\drivers\\%s.sys" ascii //weight: 1
        $x_1_2 = "Software\\3721\\AutoLive" ascii //weight: 1
        $x_1_3 = {2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_4 = "Patch\\patch29\\sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

