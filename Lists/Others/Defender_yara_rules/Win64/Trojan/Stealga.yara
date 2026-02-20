rule Trojan_Win64_Stealga_DD_2147963408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealga.DD!MTB"
        threat_id = "2147963408"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Stealer\\x64\\Release\\" ascii //weight: 10
        $x_1_2 = "DECRYPTED KEY:" ascii //weight: 1
        $x_1_3 = "NotGoodShit" ascii //weight: 1
        $x_1_4 = ".\\pipe\\GetData" ascii //weight: 1
        $x_1_5 = "[*] Key saved to" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

