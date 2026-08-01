rule Trojan_MacOS_SuspEthCallHexDecode_A_2147975100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspEthCallHexDecode.A!MTB"
        threat_id = "2147975100"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspEthCallHexDecode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl" wide //weight: 1
        $x_1_2 = "jsonrpc" wide //weight: 1
        $x_2_3 = "eth_call" wide //weight: 2
        $x_1_4 = "result" wide //weight: 1
        $x_1_5 = "xxd" wide //weight: 1
        $x_2_6 = "-r -p" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

