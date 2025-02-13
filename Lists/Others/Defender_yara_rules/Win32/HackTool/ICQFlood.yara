rule HackTool_Win32_ICQFlood_A_2147647349_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ICQFlood.A"
        threat_id = "2147647349"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ICQFlood"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ICQ Flooder by l-l00" ascii //weight: 1
        $x_1_2 = "ICQFlooder by H00K" ascii //weight: 1
        $x_2_3 = {4d 65 73 73 61 67 65 73 20 61 72 65 20 73 65 6e 74 3a 20 [0-16] 4f 66 66 6c 69 6e 65 2c 20 69 6e 63 72 65 61 73 65 20 74 69 6d 65 6f 75 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

