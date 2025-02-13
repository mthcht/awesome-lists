rule Trojan_Win32_FakeDeflab_146388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeDeflab"
        threat_id = "146388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeDeflab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2f 63 68 65 63 6b 2e 70 68 70 3f 6d 6f 64 65 3d 63 68 65 63 6b 26 74 69 64 3d 25 30 38 78 00}  //weight: 2, accuracy: High
        $x_1_2 = {4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 73 00 20 00 64 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 2e 00 20 00 50 00 72 00 65 00 73 00 73 00 20 00 4e 00 65 00 78 00 74 00 20 00 62 00 75 00 74 00 74 00 6f 00 6e 00 20 00 74 00 6f 00 20 00 63 00 6c 00 65 00 61 00 6e 00 2f 00 72 00 65 00 6d 00 6f 00 76 00 65 00 20 00 74 00 68 00 72 00 65 00 61 00 74 00 73 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {54 00 52 00 2f 00 53 00 70 00 79 00 77 00 61 00 72 00 65 00 2e 00 4e 00 54 00 41 00 50 00 2e 00 47 00 65 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 00 4d 00 2f 00 54 00 72 00 6f 00 6a 00 61 00 6e 00 2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 47 00 65 00 74 00 2e 00 35 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 61 00 70 00 73 00 65 00 72 00 76 00 65 00 72 00 2d 00 6b 00 2d 00 70 00 69 00 70 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "You use trial version of the DefenceLab Removal Tools." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

