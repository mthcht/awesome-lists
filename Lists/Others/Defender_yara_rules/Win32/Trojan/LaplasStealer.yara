rule Trojan_Win32_LaplasStealer_LK_2147847098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LaplasStealer.LK!MTB"
        threat_id = "2147847098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LaplasStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "45.159.189.105" wide //weight: 1
        $x_1_2 = "http://{0}/bot/{1}?{2}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

