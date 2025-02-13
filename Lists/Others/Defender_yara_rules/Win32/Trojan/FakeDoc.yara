rule Trojan_Win32_FakeDoc_DSK_2147755555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeDoc.DSK!MTB"
        threat_id = "2147755555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 91 d8 a2 ?? ?? 30 ?? ?? 9b}  //weight: 2, accuracy: Low
        $x_1_2 = {83 f9 20 75 ?? 33 c9 eb ?? 41 40 3b c6 72}  //weight: 1, accuracy: Low
        $x_2_3 = {8a 81 18 c5 ?? ?? 30 82 d8 bd}  //weight: 2, accuracy: Low
        $x_1_4 = {83 f9 20 75 ?? 33 c9 eb ?? 41 42 3b d6 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeDoc_DSA_2147756454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeDoc.DSA!MTB"
        threat_id = "2147756454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c8 83 e1 03 8a 91 64 fb ?? ?? 8a 8c 06 28 0e ?? ?? 32 ca 88 88 28 0e ?? ?? 75 ?? 88 ?? ?? ?? ?? ?? 40 3b c7 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeDoc_AF_2147838931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeDoc.AF!MTB"
        threat_id = "2147838931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wxanalytics.ru/net.exe" wide //weight: 1
        $x_1_2 = "appdata%\\RAC\\svcsc.exe" wide //weight: 1
        $x_1_3 = "appdata%\\RAC\\mls.exe" wide //weight: 1
        $x_1_4 = "BFA31D7B-D1D1-40D5-A90C-A0909FFA0887" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

