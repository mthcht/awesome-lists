rule Trojan_MSIL_DiscoBot_PAGG_2147931993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscoBot.PAGG!MTB"
        threat_id = "2147931993"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".passwords" wide //weight: 1
        $x_1_2 = "select * from Win32_DiskDrive" wide //weight: 1
        $x_2_3 = "discordBot" ascii //weight: 2
        $x_1_4 = "TakeScreenshot" ascii //weight: 1
        $x_2_5 = "Key Down: {0} at {1}" wide //weight: 2
        $x_2_6 = "Mouse Click:" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

