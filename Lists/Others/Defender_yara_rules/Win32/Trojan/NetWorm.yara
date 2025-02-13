rule Trojan_Win32_NetWorm_DSK_2147744497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWorm.DSK!MTB"
        threat_id = "2147744497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "alfi.exe" wide //weight: 1
        $x_1_2 = "kangen.exe" wide //weight: 1
        $x_1_3 = "AMIEN...AMIEN...AMIEN" wide //weight: 1
        $x_1_4 = "Rest In Peace... Pesin" wide //weight: 1
        $x_1_5 = "Rest In Peace... Kangen" wide //weight: 1
        $x_1_6 = "This place is not enough for us !" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

