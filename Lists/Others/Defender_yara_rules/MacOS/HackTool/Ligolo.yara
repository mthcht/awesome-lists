rule HackTool_MacOS_Ligolo_A_2147927641_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Ligolo.A!MTB"
        threat_id = "2147927641"
        type = "HackTool"
        platform = "MacOS: "
        family = "Ligolo"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LigoloDecoder" ascii //weight: 1
        $x_1_2 = "nicocha30/ligolo-ng/pkg/protocol" ascii //weight: 1
        $x_1_3 = "nicocha30/ligolo-ng/pkg/relay.StartRelay" ascii //weight: 1
        $x_1_4 = {6c 69 67 6f 6c 6f 2d 6e 67 2f 63 6d 64 2f [0-6] 2f 6d 61 69 6e 2e 67 6f}  //weight: 1, accuracy: Low
        $x_1_5 = "ListenAndServe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

