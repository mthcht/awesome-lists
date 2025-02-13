rule Trojan_MacOS_ProxyAgnt_K_2147899670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/ProxyAgnt.K!MTB"
        threat_id = "2147899670"
        type = "Trojan"
        platform = "MacOS: "
        family = "ProxyAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 ec 27 48 83 e4 f0 48 89 44 24 10 48 89 5c 24 18 48 8d 3d 41 08 b1 00 48 8d 9c 24 68 00 ff ff 48 89 5f 10 48 89 5f 18 48 89 1f 48 89 67 08 b8 00 00 00 00 0f a2 89 c6 83 f8 00 74 33 81 fb 47 65 6e 75 75 1e 81 fa 69 6e 65 49 75 16 81 f9 6e 74 65 6c 75 0e c6 05 91 ec b3 00 01 c6 05 8e ec b3 00 01}  //weight: 1, accuracy: High
        $x_1_2 = "EstablishPeerToProxyMgrRequest" ascii //weight: 1
        $x_1_3 = "*cnc.EstablishPeerToProxyMgrReply" ascii //weight: 1
        $x_1_4 = "proxymanagerConnectionDuration" ascii //weight: 1
        $x_1_5 = "cncModel.AttachReplyV2R" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

