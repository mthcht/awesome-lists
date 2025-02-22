rule Trojan_Win32_BlackWidow_GVE_2147934154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackWidow.GVE!MTB"
        threat_id = "2147934154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 07 38 05 00 [0-95] 31 d2 [0-95] f7 f3 [0-95] 8a 04 16 [0-95] 30 04 0f [0-95] 41 [0-95] 89 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

