rule Trojan_Win32_TorrentLocker_ASC_2147917081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TorrentLocker.ASC!MTB"
        threat_id = "2147917081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TorrentLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 db cf 00 00 68 67 fb 07 00 e8 ?? ?? 00 00 83 c4 08 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 81 ec 90 01 00 00 c6 45 d9 39 eb 00 c7 85}  //weight: 2, accuracy: High
        $x_1_3 = "mrosgowzty" wide //weight: 1
        $x_1_4 = "koeytusi4uytrfsehdf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

