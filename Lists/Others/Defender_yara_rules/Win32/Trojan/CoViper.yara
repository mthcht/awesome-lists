rule Trojan_Win32_CoViper_RDA_2147896828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoViper.RDA!MTB"
        threat_id = "2147896828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoViper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 85 77 fe ff ff 0f b7 95 2c fd ff ff 0f b6 85 23 fe ff ff 33 c2 88 85 23 fe ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

