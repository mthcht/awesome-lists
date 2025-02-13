rule Backdoor_MSIL_NetWire_MA_2147901838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NetWire.MA!MTB"
        threat_id = "2147901838"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 00 11 02 28 ?? ?? ?? 06 20 01 00 00 00 7e ?? ?? ?? 04 39 ?? ?? ?? ff 26 20 01 00 00 00 38 ?? ?? ?? ff 02 13 03 20 03 00 00 00 7e ?? ?? ?? 04 3a ?? ?? ?? ff 26 38 ?? ?? ?? ff 11 00 28 ?? ?? ?? 06 11 03 16 11 03 8e 69 28 ?? ?? ?? 06 13 06 38 ?? ?? ?? 00 11 00 18 6f ?? ?? ?? 0a 38 ?? ?? ?? ff dd ?? ?? ?? ff 13 02 20 02 00 00 00 fe ?? 04 00 38 ?? ?? ?? ff 38 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "PatchPolicy" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
        $x_1_6 = "Errqdggxdimk" wide //weight: 1
        $x_1_7 = "CancelPolicy" ascii //weight: 1
        $x_1_8 = "Sleep" ascii //weight: 1
        $x_1_9 = "PushInitializer" ascii //weight: 1
        $x_1_10 = "set_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

