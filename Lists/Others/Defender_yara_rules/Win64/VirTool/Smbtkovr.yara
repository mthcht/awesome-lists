rule VirTool_Win64_Smbtkovr_A_2147921628_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Smbtkovr.A"
        threat_id = "2147921628"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Smbtkovr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 bb 32 a2 df 2d 99 2b 00 00 48 3b c3 ?? ?? 48 83 65 10 00 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 48 8b 45 10 48 89 45 f0 ff ?? ?? ?? ?? ?? 8b c0 48 31 45 f0 ff ?? ?? ?? ?? ?? 8b c0 ?? ?? ?? ?? 48 31 45 f0 ff ?? ?? ?? ?? ?? 8b 45 18 ?? ?? ?? ?? 48 c1 e0 20}  //weight: 1, accuracy: Low
        $x_1_2 = {69 6d 70 61 63 6b 65 74 2e 73 6d 62 63 6f 6e 6e 65 63 74 69 6f 6e 29 03 72 06 00 00 00 69 62 76}  //weight: 1, accuracy: High
        $x_1_3 = "email._encoded_words" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

