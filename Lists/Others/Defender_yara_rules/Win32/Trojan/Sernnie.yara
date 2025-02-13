rule Trojan_Win32_Sernnie_SK_2147898862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sernnie.SK!MTB"
        threat_id = "2147898862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sernnie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InfectDrive" ascii //weight: 1
        $x_1_2 = "NetBot.vbp" ascii //weight: 1
        $x_1_3 = "u910488301.netbox001" ascii //weight: 1
        $x_1_4 = "\\OK\\BOT\\nb.exe +s +h +r" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

