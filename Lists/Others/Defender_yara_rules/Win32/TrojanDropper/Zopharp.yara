rule TrojanDropper_Win32_Zopharp_A_2147634035_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zopharp.A"
        threat_id = "2147634035"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zopharp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#tempinstpath#\\Pharming DNS.set" ascii //weight: 1
        $x_1_2 = "C:\\Windows\\system\\system.vbs" ascii //weight: 1
        $x_1_3 = "%s\\gert%i.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

