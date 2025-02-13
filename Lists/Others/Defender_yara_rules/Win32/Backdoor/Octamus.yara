rule Backdoor_Win32_Octamus_A_2147624426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Octamus.A"
        threat_id = "2147624426"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Octamus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Opactiums Bot" ascii //weight: 10
        $x_1_2 = "Stopped flooding...waiting now for commands." ascii //weight: 1
        $x_1_3 = "Problems while killing the Bot" ascii //weight: 1
        $x_1_4 = "killfirewalls" ascii //weight: 1
        $x_1_5 = "sysfuck" ascii //weight: 1
        $x_1_6 = "tmrkilldevilthings" ascii //weight: 1
        $x_1_7 = "ping 111.111.111.111" ascii //weight: 1
        $x_1_8 = "WINDOWS\\system32\\run.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

