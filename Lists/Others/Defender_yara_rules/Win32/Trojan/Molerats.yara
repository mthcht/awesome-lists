rule Trojan_Win32_Molerats_LKV_2147847994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Molerats.LKV!MTB"
        threat_id = "2147847994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Molerats"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "my.qiwi.com/Valeryi-" ascii //weight: 1
        $x_1_2 = "KABx64\\systempx.exe" ascii //weight: 1
        $x_1_3 = "process_list" ascii //weight: 1
        $x_1_4 = "avp.exe" ascii //weight: 1
        $x_1_5 = "norton.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

