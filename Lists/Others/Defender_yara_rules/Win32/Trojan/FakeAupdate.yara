rule Trojan_Win32_FakeAupdate_A_2147731290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAupdate.A"
        threat_id = "2147731290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAupdate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "crypter lumi 1.1\\final2 - Copie" ascii //weight: 1
        $x_1_2 = "DvVA/sk25NPEpdmpGtWB" ascii //weight: 1
        $x_1_3 = "adobeUpdater.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

