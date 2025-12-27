rule Ransom_Win64_RookLock_YAG_2147945573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/RookLock.YAG!MTB"
        threat_id = "2147945573"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "RookLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Wru5eirnAwojZvFOwuGfXxl+OqlY3SgYcLX88Nu5tRVwyXaFS9ym++iTByaTpxd+" ascii //weight: 5
        $x_5_2 = "iKgkykGF00HKHrbiU039hJ5BfSFlibiWkVbCLuc" ascii //weight: 5
        $x_1_3 = ".locked" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

