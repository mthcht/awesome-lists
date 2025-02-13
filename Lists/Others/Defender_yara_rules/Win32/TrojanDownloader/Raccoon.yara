rule TrojanDownloader_Win32_Raccoon_AKL_2147799512_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Raccoon.AKL!MTB"
        threat_id = "2147799512"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bd a0 ac aa bc bc cf 99 a6 bd bb ba ae a3 9f bd a0 bb aa ac bb cf 99 a6 bd bb ba ae a3 8e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

