rule Trojan_Win32_AnchorBot_SD_2147766834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AnchorBot.SD!MTB"
        threat_id = "2147766834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AnchorBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ",Control_RunDLL" ascii //weight: 1
        $x_1_2 = "runcommand(%s), pid 0" ascii //weight: 1
        $x_1_3 = "created process \"%s\", pid %i" ascii //weight: 1
        $x_1_4 = "where guid? who will do it?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

