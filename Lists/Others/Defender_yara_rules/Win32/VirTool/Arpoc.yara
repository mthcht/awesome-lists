rule VirTool_Win32_Arpoc_B_2147615078_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Arpoc.B"
        threat_id = "2147615078"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Arpoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".\\\\x\\..\\..\\xxxxxxxx" wide //weight: 1
        $x_1_2 = "WAHAHAH %d %08x" ascii //weight: 1
        $x_1_3 = "ncacn_np" ascii //weight: 1
        $x_1_4 = {68 80 b1 40 00 68 8c b5 40 00 8b 45 dc 50 e8 5e 06 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

