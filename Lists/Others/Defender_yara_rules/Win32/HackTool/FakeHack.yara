rule HackTool_Win32_FakeHack_2147708852_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/FakeHack"
        threat_id = "2147708852"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeHack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "52f4dcaa-43d9-45d1-a603-d42993225ba5" ascii //weight: 10
        $x_10_2 = "LOLToolStripMenuItem" ascii //weight: 10
        $x_1_3 = "ContactSupportToolStripMenuItem" ascii //weight: 1
        $x_1_4 = {41 63 74 69 76 61 74 65 30 00 54 6f 6f 6c 53 74 72 69 70 4d 65 6e 75 49 74 65 6d}  //weight: 1, accuracy: Low
        $x_1_5 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 31 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

