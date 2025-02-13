rule VirTool_Win32_Samdumpz_A_2147846208_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Samdumpz.A!dll"
        threat_id = "2147846208"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Samdumpz"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 05 ff 74 24 40 ff 15 ?? ?? ?? ?? 33 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {50 68 ff ff 00 00 8d 44 ?? ?? 50 6a 00 8d 44 ?? ?? 50 ff 74 24 44 ff 54 24 28 89 44 24 64}  //weight: 1, accuracy: Low
        $x_1_3 = {50 6a 00 68 00 00 10 00 ff ?? 8b f8}  //weight: 1, accuracy: Low
        $x_1_4 = {50 6a 12 ff 74 24 2c ff 54 ?? ?? 85 c0 0f 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Samdumpz_B_2147846209_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Samdumpz.B!dll"
        threat_id = "2147846209"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Samdumpz"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 68 ff 0f 0f 00 8d 44 ?? ?? 89 5c 24 78 50 6a 00 89 9c 24 84 00 00 00 89 9c 24 88 00 00 00 89 9c 24 8c 00 00 00 c7 44 24 78 18 00 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 01 68 00 00 00 02 8d 44 ?? ?? 50 6a 00 ff 54 ?? ?? 85 c0 0f 88}  //weight: 1, accuracy: Low
        $x_1_3 = {50 68 ff ff 00 00 8d 44 ?? ?? 50 6a 00 8d 44 ?? ?? 50 ff 74 24 40 ff 54 ?? ?? 89 44 24 54}  //weight: 1, accuracy: Low
        $x_1_4 = {50 6a 00 68 00 00 10 00 ff ?? 8b f0 89 74 24 5c 85 f6 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

