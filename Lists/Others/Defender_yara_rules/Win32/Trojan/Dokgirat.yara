rule Trojan_Win32_Dokgirat_A_2147730332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dokgirat.A"
        threat_id = "2147730332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dokgirat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Final1stspy\\LoadDll\\Release\\LoadDll.pdb" ascii //weight: 1
        $x_1_2 = {8a 14 39 80 c2 ?? 80 f2 ?? 88 14 39 41 3b ce 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dokgirat_D_2147896537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dokgirat.D!MTB"
        threat_id = "2147896537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dokgirat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\final1stspy\\loaddll\\release\\loaddll.pdb" ascii //weight: 1
        $x_1_2 = {8a 14 39 80 c2 7a 80 f2 19 88 14 39 41 3b ce 7c ef}  //weight: 1, accuracy: High
        $x_1_3 = {80 34 38 50 40 3b c6 7c f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

