rule Worm_Win32_Zombaque_A_2147638845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Zombaque.A"
        threat_id = "2147638845"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Zombaque"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Wasting CPU time" ascii //weight: 1
        $x_1_2 = "Intelligent P2P Zombie" ascii //weight: 1
        $x_1_3 = "Made in USSR" ascii //weight: 1
        $x_1_4 = "qwertyuilkjhzxcv" ascii //weight: 1
        $x_1_5 = "tmp %systemroot%\\system32\\ipz" ascii //weight: 1
        $x_1_6 = "%d %02d:%02d:%02d] %s" ascii //weight: 1
        $x_1_7 = "#%d (PASS) received connection from %s" ascii //weight: 1
        $x_1_8 = "1q2w3e4r5t" ascii //weight: 1
        $x_1_9 = "billgates" ascii //weight: 1
        $x_1_10 = "darthvader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

