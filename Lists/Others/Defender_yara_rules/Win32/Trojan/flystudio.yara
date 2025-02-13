rule Trojan_Win32_flystudio_KA_2147890152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/flystudio.KA!MTB"
        threat_id = "2147890152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "flystudio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shunqian.tooo.top" ascii //weight: 1
        $x_1_2 = "Users\\Public\\xiaodaxzqxia" ascii //weight: 1
        $x_1_3 = "HttpOpenRequestA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

