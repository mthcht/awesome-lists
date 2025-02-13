rule VirTool_Win64_Samdumpz_A_2147846210_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Samdumpz.A!dll"
        threat_id = "2147846210"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Samdumpz"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 57 c0 0f 57 c9 4c 8d ?? ?? 48 8d ?? ?? 41 b8 ff 0f 0f 00 33 c9 89 7d ff c7 45 e7 30 00 00 00 f3 0f 7f 45 ef f3 0f 7f 4d 07 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 4d 87 48 8d ?? ?? 4c 8d ?? ?? 48 89 44 24 28 48 8d ?? ?? 45 33 c0 c7 44 24 20 ff ff 00 00 ff ?? ?? 89 45 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 4c 24 38 4c 8d ?? ?? ba 12 00 00 00 41 ff ?? 85 c0 0f 88}  //weight: 1, accuracy: Low
        $x_1_4 = {33 d2 4c 8b c6 8d 4a ?? ff 15 ?? ?? ?? ?? 4c 8b f8 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Samdumpz_B_2147846211_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Samdumpz.B!dll"
        threat_id = "2147846211"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Samdumpz"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4d a7 4c 8d ?? ?? ba 05 00 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b 45 af 48 8b 4d 9f 4c 8d ?? ?? 4d 8b 40 10 ba ff 07 0f 00 ff ?? 85 c0 0f}  //weight: 1, accuracy: Low
        $x_1_3 = {33 d2 4c 8b c7 8d 4a ?? ff 15 ?? ?? ?? ?? 4c 8b f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

