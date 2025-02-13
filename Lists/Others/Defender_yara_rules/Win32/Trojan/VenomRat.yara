rule Trojan_Win32_VenomRat_AVM_2147902074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VenomRat.AVM!MTB"
        threat_id = "2147902074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VenomRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 4c 24 38 88 4c 24 42 88 4c 24 47 c6 44 24 34 78 c6 44 24 35 61 88 54 24 3a c6 44 24 3e 66 c6 44 24 41 33 c6 44 24 43 3b c6 44 24 44 74 88 54 24 46 c6 44 24 40 0a c6 44 24 39 62 c7 44 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VenomRat_RPX_2147902375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VenomRat.RPX!MTB"
        threat_id = "2147902375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VenomRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 05 0c 00 0f 80 9b 00 00 00 0f bf c8 51 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d8 ff d7 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

