rule Trojan_Win32_NpmSteal_MU_2147973165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NpmSteal.MU!MTB"
        threat_id = "2147973165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NpmSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "global[_$_" wide //weight: 1
        $x_1_2 = "var _$_" wide //weight: 1
        $x_1_3 = "fromcharcode" wide //weight: 1
        $x_1_4 = "charat" wide //weight: 1
        $x_1_5 = "global['_v']=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

