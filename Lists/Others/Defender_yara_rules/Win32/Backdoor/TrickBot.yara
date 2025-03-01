rule Backdoor_Win32_TrickBot_ZZD_2147766677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/TrickBot.ZZD!dha"
        threat_id = "2147766677"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/></moduleconfig>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

