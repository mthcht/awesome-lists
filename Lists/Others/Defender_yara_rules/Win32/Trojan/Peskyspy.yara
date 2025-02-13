rule Trojan_Win32_Peskyspy_A_2147627882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Peskyspy.A"
        threat_id = "2147627882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Peskyspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/test/input_ng.php" ascii //weight: 1
        $x_1_2 = "_CONFIG_SILENT_MODE_" ascii //weight: 1
        $x_1_3 = "_CONFIG_UPLOAD_" ascii //weight: 1
        $x_1_4 = "Delete VoIP-Recorder" ascii //weight: 1
        $x_1_5 = "lookup.out" ascii //weight: 1
        $x_1_6 = "skype.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

