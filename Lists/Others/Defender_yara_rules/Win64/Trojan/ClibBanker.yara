rule Trojan_Win64_ClibBanker_VG_2147980480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClibBanker.VG!MTB"
        threat_id = "2147980480"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClibBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CPMARK::instance_mutex::Global\\CP1db9936cfb0af03e" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "CPMARK::dogecoin::DQNbjWcKD6PctKqkAG4BdhCRHY9uFv3u9x" ascii //weight: 1
        $x_1_4 = "CPMARK::solana::" ascii //weight: 1
        $x_1_5 = "CPMARK::bitcoin_taproot::" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

