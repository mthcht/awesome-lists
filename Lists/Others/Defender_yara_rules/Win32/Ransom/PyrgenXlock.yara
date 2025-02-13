rule Ransom_Win32_PyrgenXlock_SK_2147753006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/PyrgenXlock.SK!MTB"
        threat_id = "2147753006"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "PyrgenXlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xInclude\\pyconfig.h" ascii //weight: 1
        $x_2_2 = "xbitcoin.bmp" ascii //weight: 2
        $x_2_3 = "xlock.bmp" ascii //weight: 2
        $x_2_4 = "xlock.ico" ascii //weight: 2
        $x_1_5 = "xruntime.cfg" ascii //weight: 1
        $x_1_6 = "zout00-PYZ.pyz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

