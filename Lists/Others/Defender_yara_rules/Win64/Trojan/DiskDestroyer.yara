rule Trojan_Win64_DiskDestroyer_A_2147851651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiskDestroyer.A!MTB"
        threat_id = "2147851651"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiskDestroyer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\.\\PhysicalDrive" ascii //weight: 2
        $x_2_2 = "Write Disk Sucess" ascii //weight: 2
        $x_2_3 = "your data in Disk has been encrypted" ascii //weight: 2
        $x_2_4 = "Your PC has been destroyed by" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

