rule Trojan_Win64_PSWDump_MX_2147955786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PSWDump.MX!MTB"
        threat_id = "2147955786"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PSWDump"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 03 48 85 c0 74 09 e8 22 07 01 00 85 c0 75 0b 48 83 c3 08 48 3b df 75 e6 33 c0 48 8b 5c 24 30 48 83 c4 20}  //weight: 1, accuracy: High
        $x_1_2 = "Global\\ChromeDecryptWorkDoneEvent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

