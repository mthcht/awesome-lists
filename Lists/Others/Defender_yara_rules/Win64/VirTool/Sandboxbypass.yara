rule VirTool_Win64_Sandboxbypass_A_2147686038_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Sandboxbypass.A"
        threat_id = "2147686038"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Sandboxbypass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 c1 02 00 00 00 ff 15 ?? ?? 00 00 48 8b c8 48 c7 c2 02 00 00 00 48 83 ec 30 49 c7 c0 00 10 00 00 4c 89 44 24 20 4d 33 c0 4d 8b c8 ff 15 ?? ?? 00 00 48 8b 4d f8 48 89 08 48 33 c9 ff 15 ?? ?? 00 00 [0-5] 69 65 66 72 61 6d 65 2e 64 6c 6c 00 66 6d 36 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

