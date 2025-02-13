rule Trojan_Win32_MammonRansom_YAN_2147929986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MammonRansom.YAN!MTB"
        threat_id = "2147929986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MammonRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".goodluck" ascii //weight: 1
        $x_1_2 = "C:\\Keylock\\id.txt" ascii //weight: 1
        $x_1_3 = "C:\\Keylock\\pb.txt" ascii //weight: 1
        $x_1_4 = "Keylock\\ky.DAT" ascii //weight: 1
        $x_10_5 = "G:\\Mammon\\Release\\Mammon.pdb" ascii //weight: 10
        $x_1_6 = {69 6e 20 63 61 73 65 20 6f 66 20 6e 6f 20 61 6e 73 77 65 72 20 62 61 63 6b 75 70 20 65 6d 61 69 6c 3a [0-32] 40 67 6d 61 69 6c 2e 63 6f 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

