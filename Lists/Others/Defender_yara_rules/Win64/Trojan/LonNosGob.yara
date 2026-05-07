rule Trojan_Win64_LonNosGob_DA_2147968690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LonNosGob.DA!MTB"
        threat_id = "2147968690"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LonNosGob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID: \"JSjBQ1K4-23F-Lnd" ascii //weight: 1
        $x_1_2 = "Go build ID: \"Y90ruIn2CGgk0qsj" ascii //weight: 1
        $x_1_3 = "Go build ID: \"w68wAOGa2iN6SCP-" ascii //weight: 1
        $x_1_4 = "Go build ID: \"YWyhFN_3ElyyaeqB" ascii //weight: 1
        $x_1_5 = "Go build ID: \"ONGIURMZjHu45NAT" ascii //weight: 1
        $x_1_6 = "Go build ID: \"-wbWQIHuv2VOdGOo" ascii //weight: 1
        $x_1_7 = "Go build ID: \"8Y5WVpK01Wa34sSa" ascii //weight: 1
        $x_1_8 = "Go build ID: \"NBJQ_dzyKZXI50HC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

