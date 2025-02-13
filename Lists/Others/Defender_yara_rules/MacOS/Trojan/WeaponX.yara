rule Trojan_MacOS_WeaponX_A_2147745316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/WeaponX.A!MTB"
        threat_id = "2147745316"
        type = "Trojan"
        platform = "MacOS: "
        family = "WeaponX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.nemo.kext.WeaponX" ascii //weight: 1
        $x_1_2 = "/Users/nemo/Coding/WeaponX/" ascii //weight: 1
        $x_1_3 = "_WeaponX_start" ascii //weight: 1
        $x_1_4 = "_hooked_getdirentries" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

