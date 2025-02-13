rule Trojan_Win32_Moxtrarch_A_2147680211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Moxtrarch.A"
        threat_id = "2147680211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Moxtrarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://egopay.ru/num/" ascii //weight: 1
        $x_2_2 = {33 2e 20 c4 eb ff 20 e7 e0 e2 e5 f0 f8 e5 ed e8 ff 20 e7 e0 e3 f0 f3 e7 ea e8 20 ed e5 ee e1 f5}  //weight: 2, accuracy: High
        $x_2_3 = {c8 d7 cd c0 df 20 ce d4 c5 d0 d2 c0 20 ce c1 20 c8 d1 cf ce cb dc c7 ce c2 c0 cd c8 c8 20 d1 c5}  //weight: 2, accuracy: High
        $x_3_4 = "http://counter.moneyextre.me/addsubscription.php?abon=7" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

