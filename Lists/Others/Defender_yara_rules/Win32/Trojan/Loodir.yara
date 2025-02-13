rule Trojan_Win32_Loodir_A_2147689966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Loodir.A"
        threat_id = "2147689966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Loodir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\DiskDataMgr" ascii //weight: 1
        $x_1_2 = {81 bc 11 20 03 00 00 aa 99 88 77 75 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

