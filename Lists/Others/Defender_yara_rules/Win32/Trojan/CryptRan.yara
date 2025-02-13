rule Trojan_Win32_CryptRan_SA_2147743087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptRan.SA!MTB"
        threat_id = "2147743087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 03 32 06 46 4f 75 ?? be ?? ?? ?? ?? bf 09 00 00 00 88 03 83 f9 00 74 ?? 4b 49 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "csrfcyctctccccs.sie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

