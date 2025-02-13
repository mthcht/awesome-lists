rule Trojan_MacOS_ColdRoot_B_2147745679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/ColdRoot.B!MTB"
        threat_id = "2147745679"
        type = "Trojan"
        platform = "MacOS: "
        family = "ColdRoot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "H_RemoteDesktop Requested .." ascii //weight: 1
        $x_1_2 = "/private/var/tmp/runme.sh" ascii //weight: 1
        $x_1_3 = "COLDZER0_OK" ascii //weight: 1
        $x_1_4 = "Coded By Coldzer0 / Skype:Coldzer01" ascii //weight: 1
        $x_1_5 = {c6 40 38 01 8d 83 2f d1 1b 00 e8 ?? ?? ?? ?? eb 15 8b 83 83 22 1e 00 c6 40 38 00 8d 83 5b d1 1b 00 e8 ?? ?? ?? ?? 8d 83 83 d1 1b 00 e8 ?? ?? ?? ?? 8b 83 83 22 1e 00 83 78 48 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

