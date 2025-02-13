rule Trojan_Win64_Hax_A_2147852695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Hax.A!MTB"
        threat_id = "2147852695"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Hax"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "eg: ms16-032 \"whoami /all" ascii //weight: 2
        $x_2_2 = "usage: ms16-032 command" ascii //weight: 2
        $x_2_3 = "WinSta0\\Default" wide //weight: 2
        $x_2_4 = "%ws was assigned" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

