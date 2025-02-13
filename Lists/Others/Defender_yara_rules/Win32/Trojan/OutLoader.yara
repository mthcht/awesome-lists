rule Trojan_Win32_OutLoader_MA_2147835132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OutLoader.MA!MTB"
        threat_id = "2147835132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "139.180.138.226" wide //weight: 10
        $x_10_2 = "/out.txt" wide //weight: 10
        $x_10_3 = "%ws\\%hs.xls" wide //weight: 10
        $x_10_4 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 5c 00 6d 00 79 00 61 00 70 00 70 00 2e 00 78 00 6c 00 73}  //weight: 10, accuracy: High
        $x_1_5 = "DocumentSummaryInformation" wide //weight: 1
        $x_1_6 = "WinHttpQueryDataAvailable" ascii //weight: 1
        $x_1_7 = "WinHttpSendRequest" ascii //weight: 1
        $x_1_8 = "CryptDecrypt" ascii //weight: 1
        $x_1_9 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

