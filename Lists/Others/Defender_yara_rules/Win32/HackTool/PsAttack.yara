rule HackTool_Win32_PsAttack_A_2147716542_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PsAttack.A"
        threat_id = "2147716542"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PsAttack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

