rule Trojan_Win64_Skeeyah_MG_2147923416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Skeeyah.MG!MTB"
        threat_id = "2147923416"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Skeeyah"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 eb 38 48 63 05 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 48 03 c1 81 38 50 45}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\re\\jdk7u45\\229\\build\\windows-amd64\\tmp\\sun\\launcher\\servertool\\obj64\\servertool.pdb" ascii //weight: 1
        $x_1_3 = "1.7.0_45-b18" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Skeeyah_MG_2147923416_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Skeeyah.MG!MTB"
        threat_id = "2147923416"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Skeeyah"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 eb 38 48 63 05 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 48 03 c1 81 38 50 45}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\re\\jdk7u45\\229\\build\\windows-amd64\\tmp\\sun\\launcher\\servertool\\obj64\\servertool.pdb" ascii //weight: 1
        $x_1_3 = "1.7.0_45-b18" wide //weight: 1
        $x_1_4 = "jli.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

