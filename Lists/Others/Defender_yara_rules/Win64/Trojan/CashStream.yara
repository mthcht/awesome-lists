rule Trojan_Win64_CashStream_ZZ_2147905746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CashStream.ZZ"
        threat_id = "2147905746"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CashStream"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "221"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {41 0f b6 02 4d 8d 52 01 44 33 c8 41 8b c1 d1 e8 8b c8 81 f1 78 3b f6 82 41 80 e1 01 0f 44 c8 8b c1 d1 e8 8b d0 81 f2 78 3b f6 82 80 e1 01 0f 44 d0}  //weight: 100, accuracy: High
        $x_100_3 = "0014br.gov.bcb.pix" ascii //weight: 100
        $x_10_4 = "cbMonitor" ascii //weight: 10
        $x_10_5 = "tcp://127.0.0.1:%hu" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

