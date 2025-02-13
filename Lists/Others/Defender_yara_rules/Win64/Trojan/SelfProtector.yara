rule Trojan_Win64_SelfProtector_A_2147752875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SelfProtector.A"
        threat_id = "2147752875"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SelfProtector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "winhost.exe" wide //weight: 10
        $x_10_2 = "nheqminer.exe" wide //weight: 10
        $x_5_3 = "TMethodImplementationIntercept" ascii //weight: 5
        $x_5_4 = "Hooked APIs" wide //weight: 5
        $x_10_5 = {48 89 f3 8b 03 48 8d 34 03 48 8b 4e 40 48 8d 15 42 00 00 00 e8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

