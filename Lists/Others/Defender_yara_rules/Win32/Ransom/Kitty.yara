rule Ransom_Win32_Kitty_GA_2147776493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Kitty.GA!MTB"
        threat_id = "2147776493"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Kitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HelloKittyMutex" ascii //weight: 10
        $x_1_2 = "decrypt" ascii //weight: 1
        $x_1_3 = ".onion" ascii //weight: 1
        $x_1_4 = " pay " ascii //weight: 1
        $x_1_5 = "ShadowCopy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

