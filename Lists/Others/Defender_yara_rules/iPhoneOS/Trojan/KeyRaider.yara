rule Trojan_iPhoneOS_KeyRaider_A_2147796980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/KeyRaider.A!xp"
        threat_id = "2147796980"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "KeyRaider"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mischa07" ascii //weight: 1
        $x_1_2 = "www.wushidou.cn" ascii //weight: 1
        $x_1_3 = "/Library/MobileSubstrate/DynamicLibraries/iwexin.dylib" ascii //weight: 1
        $x_1_4 = "/usr/lib/libMobileGestalt.dylib" ascii //weight: 1
        $x_1_5 = "POST /WebObjects/MZFinance.woa/wa" ascii //weight: 1
        $x_1_6 = "hookaid" ascii //weight: 1
        $x_1_7 = "iappstore" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

