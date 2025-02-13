rule Backdoor_Win32_StoredBt_A_2147638960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/StoredBt.A"
        threat_id = "2147638960"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "StoredBt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Result: [Success to launch rcvnc command %s:%d]" ascii //weight: 2
        $x_2_2 = "/_cmn/INI/ca.ini" ascii //weight: 2
        $x_3_3 = "capture is successful. check the LOG directory after a few minutes." ascii //weight: 3
        $x_2_4 = "InternalCommand: [btstop]" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

