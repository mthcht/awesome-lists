rule TrojanSpy_AndroidOS_WhatsSpy_A_2147846501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/WhatsSpy.A!MTB"
        threat_id = "2147846501"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "WhatsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/WS Sent/sent_" ascii //weight: 1
        $x_1_2 = "/WS Recibed/" ascii //weight: 1
        $x_1_3 = "/WS Private/" ascii //weight: 1
        $x_1_4 = "Send_WSRecibed" ascii //weight: 1
        $x_1_5 = "Send_WSsend" ascii //weight: 1
        $x_1_6 = "myGallerysWS.json" ascii //weight: 1
        $x_1_7 = "myGallerysWSSend.json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

