rule Trojan_Win64_ShellcodeMarte_AMAG_2147913752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeMarte.AMAG!MTB"
        threat_id = "2147913752"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeMarte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b d3 48 8b c8 48 8b f8 4c 89 6c 24 20 ff 15 ?? ?? ?? ?? 48 8b cf ff 15 ?? ?? ?? ?? b9 60 ea 00 00 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {99 83 e2 1f 03 c2 c1 f8 05 0f af c3 c1 e0 02 8b f8 8d 48 36 89 4d c1 b9 ?? ?? ?? ?? 66 89 4d bf 8b c8}  //weight: 2, accuracy: Low
        $x_1_3 = "Application Data\\quickScreenShot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

