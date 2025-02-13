rule Trojan_Win32_PhisherAgt_2147782115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PhisherAgt!MTB"
        threat_id = "2147782115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PhisherAgt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ownerid" ascii //weight: 1
        $x_1_2 = "init_iv" ascii //weight: 1
        $x_1_3 = "https://keyauth.com/api/v3/" wide //weight: 1
        $x_1_4 = "success" ascii //weight: 1
        $x_1_5 = "invalidver" ascii //weight: 1
        $x_1_6 = "download" ascii //weight: 1
        $x_1_7 = "hwid" ascii //weight: 1
        $x_1_8 = "info" ascii //weight: 1
        $x_1_9 = "expiry" ascii //weight: 1
        $x_1_10 = "&init_iv=a8981e5552e7326af8b7411d3eb4a9dce78dc7339e5a7b29027879c093b8853e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

