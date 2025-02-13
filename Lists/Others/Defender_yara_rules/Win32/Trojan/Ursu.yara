rule Trojan_Win32_Ursu_NBA_2147927131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursu.NBA!MTB"
        threat_id = "2147927131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vshcso.txe ek-n tevssc" ascii //weight: 2
        $x_1_2 = "Service-0x0-3e7$\\default" ascii //weight: 1
        $x_1_3 = "eknrle23" ascii //weight: 1
        $x_1_4 = "daavip23" ascii //weight: 1
        $x_1_5 = "AcSvcst.dll" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost\\netsvcs" ascii //weight: 1
        $x_1_7 = "GetKeyboardType" ascii //weight: 1
        $x_1_8 = "Final2.dll" ascii //weight: 1
        $x_1_9 = "CreatePotPlayerExA" ascii //weight: 1
        $x_1_10 = "decode" ascii //weight: 1
        $x_1_11 = "encode" ascii //weight: 1
        $x_1_12 = "CreatePotPlayerExW" ascii //weight: 1
        $x_1_13 = "DestroyPotPlayer" ascii //weight: 1
        $x_1_14 = "OpenPotPlayerUrlW" ascii //weight: 1
        $x_1_15 = "washinject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

