rule Trojan_Win64_LunexStealer_MK_2147982109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LunexStealer.MK!MTB"
        threat_id = "2147982109"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LunexStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[*] === lunex debug log %04u-%02u-%02u %02u:%02u:%02u ===" ascii //weight: 10
        $x_5_2 = "%%LOCALAPPDATA%%\\lunex\\logs.txt" ascii //weight: 5
        $x_3_3 = "[*] Closing browsers for data dump..." ascii //weight: 3
        $x_2_4 = "[*] Wallets: uploaded %d archive(s)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

