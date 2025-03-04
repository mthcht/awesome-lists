rule Trojan_Win32_SdBot_ARAA_2147906068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SdBot.ARAA!MTB"
        threat_id = "2147906068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SdBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/crackman2/irc_mcgee/raw/master/update/irc_mcgee.exe" ascii //weight: 2
        $x_2_2 = "@!forceupdate" ascii //weight: 2
        $x_3_3 = "ADgAAAC5laF9mcmFtZQA=" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

