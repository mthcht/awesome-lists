rule Trojan_Win64_PhantomKiller_DA_2147969756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PhantomKiller.DA!MTB"
        threat_id = "2147969756"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PhantomKiller"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\BootRepair" ascii //weight: 1
        $x_1_2 = "[-] open device failed: %d" ascii //weight: 1
        $x_1_3 = "[+] killed %d" ascii //weight: 1
        $x_1_4 = "[-] ioctl failed: %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

