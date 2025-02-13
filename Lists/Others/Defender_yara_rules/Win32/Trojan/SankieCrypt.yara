rule Trojan_Win32_SankieCrypt_SN_2147764994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SankieCrypt.SN!MTB"
        threat_id = "2147764994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SankieCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://entws3ax.c1.biz/gate.php" ascii //weight: 1
        $x_1_2 = "http://5ndisjtu.c1.biz/start.php?usr=%1&cmp=%2&k=%3" ascii //weight: 1
        $x_1_3 = "----HiHtTpClIeNt" ascii //weight: 1
        $x_1_4 = "http://5ndisjtu.c1.biz/data/get.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

