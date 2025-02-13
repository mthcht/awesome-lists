rule Trojan_AndroidOS_Boqx_A_2147817429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Boqx.A!MTB"
        threat_id = "2147817429"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Boqx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {12 00 38 07 53 00 1a 01 ?? ?? 1a 04 ?? ?? 1a 05 00 00 6e 30 ?? ?? 42 05 0c 02 22 04 ?? ?? 71 10 ?? ?? 01 00 0c 05 70 20 ?? ?? 54 00 1a 05 ?? ?? 6e 20 ?? ?? 52 00 0a 05 6e 20 ?? ?? 52 00 0c 05 6e 20 ?? ?? 54 00 0c 04 6e 10 ?? ?? 04 00 0c 01 12 04 1a 05 ?? ?? 6e 20 ?? ?? 52 00 0a 05 6e 30 ?? ?? 42 05 0c 02 22 03 ?? ?? 70 20 ?? ?? 13 00 6e 10 ?? ?? 03 00 0c 00 1f 00}  //weight: 1, accuracy: Low
        $x_1_2 = "getFileByUrl" ascii //weight: 1
        $x_1_3 = "isPreferredAPNCmwap" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

