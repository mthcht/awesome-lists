rule VirTool_Win32_Nosrawec_A_2147636436_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Nosrawec.A"
        threat_id = "2147636436"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Nosrawec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 68 40 06 00 00 8d 85 7d f9 ff ff 50 8b 45 ec 50 e8}  //weight: 1, accuracy: High
        $x_1_2 = {53 63 68 77 61 72 7a 65 20 53 6f 6e 6e 65 20 52 41 54 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

