rule VirTool_Win32_Makarand_A_2147945320_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Makarand.A"
        threat_id = "2147945320"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Makarand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a2VybmVsMzIuZGxs" ascii //weight: 1
        $x_1_2 = "bnRkbGwuZGxs" ascii //weight: 1
        $x_1_3 = "TG9hZExpYnJhcnlB" ascii //weight: 1
        $x_1_4 = "R2V0UHJvY0FkZHJlc3M" ascii //weight: 1
        $x_1_5 = "VmlydHVhbFByb3RlY3Q" ascii //weight: 1
        $x_1_6 = "YW1zaS5kbGw" ascii //weight: 1
        $x_1_7 = "QW1zaVNjYW5CdWZmZXI" ascii //weight: 1
        $x_1_8 = "RXR3RXZlbnRXcml0ZQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

