rule Trojan_MSIL_Swrort_B_2147785247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Swrort.B!MTB"
        threat_id = "2147785247"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Swrort"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 30 03 00 32 00 00 00 03 00 00 11 28 03 00 00 06 0a 20 10 27 00 00 28 ?? 00 00 0a 28 03 00 00 06 0b 06 1f 32 2f 09 06 1f 0a 58 07 2e 0e 17 2a 1f 3c 06 59 1f 0a 07 59 2e 02 17 2a 16 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {13 30 04 00 32 00 00 00 06 00 00 11 28 ?? 00 00 0a 0b 12 01 28 ?? 00 00 0a 16 28 ?? 00 00 0a 73 ?? 00 00 0a 0a 7e ?? 00 00 04 06 16 1f 19 6f ?? 00 00 0a 8f ?? 00 00 01 28 ?? 00 00 0a 2a}  //weight: 1, accuracy: Low
        $x_1_3 = "http://222.139.151.114/logs/Song/officeupdatem.exe" wide //weight: 1
        $x_1_4 = "Office ClickToRun Service Update Monitors" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

