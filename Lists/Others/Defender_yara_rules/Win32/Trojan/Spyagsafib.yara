rule Trojan_Win32_Spyagsafib_R_2147899225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spyagsafib.R!MTB"
        threat_id = "2147899225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spyagsafib"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "topic=setupcmdline" wide //weight: 1
        $x_1_2 = "/verysilent /password=" wide //weight: 1
        $x_1_3 = "PasswordSalt" ascii //weight: 1
        $x_1_4 = "{userappdata}\\imagefile" wide //weight: 1
        $x_1_5 = "InnoSetupLdrWindow" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

