rule VirTool_Win64_PrivEscDcom_A_2147931566_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/PrivEscDcom.A"
        threat_id = "2147931566"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PrivEscDcom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 48 a5 4c 89 e1 48 8b 74 24 f8 48 8b 7c 24 f0 4c 8b 64 24 e8 ff}  //weight: 1, accuracy: High
        $x_1_2 = {4c 8b 7b 08 48 89 7c 24 38 c7 44 24 30 7b 00 00 00 83 64 24 28 00 c7 44 24 20 09 02 00 00 4c 89 f9 ba 03 00 00 00 45 31 c0 41 b9 ff 00 00 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = "D:(A;OICI;GA;;;WD)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

