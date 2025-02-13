rule Trojan_Win32_ShellcodeRunz_A_2147918568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunz.A!MTB"
        threat_id = "2147918568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1d bf a8 1d 1d bf a8 1d 1d bf a1 65 8e bf a6 1d 1d bf 6b 9e 1e be a1 1d 1d bf 6b 9e 19 be a4 1d 1d bf 6b 9e 18 be 80 1d 1d bf a8 1d 1c bf 15 1d 1d bf a8 1d 1d bf b5 1d 1d bf bc 99 e2 bf a9 1d 1d bf bc 99 1f be a9 1d 1d bf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

