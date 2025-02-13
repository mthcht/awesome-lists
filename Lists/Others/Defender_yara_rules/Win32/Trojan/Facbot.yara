rule Trojan_Win32_Facbot_A_2147682020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Facbot.A"
        threat_id = "2147682020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Facbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProfileVisitor.plugin.fklibiilhlpjiobhfbchfndcobegnohh." ascii //weight: 1
        $x_1_2 = "*://*.facebook.com/\", \"tabs\", \"cookies\", \"notifications\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

