rule TrojanDownloader_Win32_Ranbyus_A_2147621588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ranbyus.A"
        threat_id = "2147621588"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranbyus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 f7 ac 30 e0 88 07 47 84 c0 74 02 eb f4}  //weight: 2, accuracy: High
        $x_1_2 = {31 d2 4a 39 d0 74 e8 89 c7 8d 43}  //weight: 1, accuracy: High
        $x_1_3 = {78 2e 6c 63 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

