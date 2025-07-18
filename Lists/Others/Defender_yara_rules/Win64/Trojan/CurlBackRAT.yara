rule Trojan_Win64_CurlBackRAT_PSR_2147946854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CurlBackRAT.PSR!MTB"
        threat_id = "2147946854"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CurlBackRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/dnammocmvitna" ascii //weight: 1
        $x_1_2 = "anti-vm.txt" ascii //weight: 1
        $x_1_3 = "NO CPU FAN FOUND , EXITING !" ascii //weight: 1
        $x_1_4 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

