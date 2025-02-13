rule Trojan_Win32_Sopus_A_2147723335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sopus.A"
        threat_id = "2147723335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sopus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6a 77 58 66 89 85 40 ff ff ff 6a 71 58 66 89 85 42 ff ff ff 6a 67 58 66 89 85 44 ff ff ff 6a 70 58}  //weight: 5, accuracy: High
        $x_5_2 = {68 22 f0 1f cb 6a 0a e8}  //weight: 5, accuracy: High
        $x_5_3 = {68 02 cf 7b a4 6a 02 e8}  //weight: 5, accuracy: High
        $x_1_4 = "ns1.sourpuss.net" ascii //weight: 1
        $x_1_5 = "civet.ziphaze.com" ascii //weight: 1
        $x_1_6 = "ns2.sourpuss.net" ascii //weight: 1
        $x_1_7 = "ns.clusterweb.com" ascii //weight: 1
        $x_1_8 = "ns.dotbit.me" ascii //weight: 1
        $x_1_9 = "secondary.server.edv-froehlich.de" ascii //weight: 1
        $x_1_10 = "philipostendorf.de" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sopus_B_2147723336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sopus.B"
        threat_id = "2147723336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sopus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {68 0b f6 1f cb 6a 0a e8}  //weight: 10, accuracy: High
        $x_10_2 = {68 95 5b 28 03 6a 01 e8}  //weight: 10, accuracy: High
        $x_10_3 = {68 20 5d 35 5b 6a 0a e8}  //weight: 10, accuracy: High
        $x_10_4 = {68 23 27 a5 91 6a 06 e8}  //weight: 10, accuracy: High
        $x_1_5 = "alors.deepdns.cryptostorm.net" ascii //weight: 1
        $x_1_6 = "anyone.dnsrec.meo.ws" ascii //weight: 1
        $x_1_7 = "anytwo.dnsrec.meo.ws" ascii //weight: 1
        $x_1_8 = "civet.ziphaze.com" ascii //weight: 1
        $x_1_9 = "ist.fellig.org" ascii //weight: 1
        $x_1_10 = "ns.dotbit.me" ascii //weight: 1
        $x_1_11 = "ns1.any.dns.d0wn.biz" ascii //weight: 1
        $x_1_12 = "ns1.domaincoin.net" ascii //weight: 1
        $x_1_13 = "ns1.nl.dns.d0wn.biz" ascii //weight: 1
        $x_1_14 = "ns1.random.dns.d0wn.biz" ascii //weight: 1
        $x_1_15 = "ns1.sg.dns.d0wn.biz" ascii //weight: 1
        $x_1_16 = "ns1.sourpuss.net" ascii //weight: 1
        $x_1_17 = "ns1.syd.dns.lchi.mp" ascii //weight: 1
        $x_1_18 = "ns2.domaincoin.net" ascii //weight: 1
        $x_1_19 = "ns2.fr.dns.d0wn.biz" ascii //weight: 1
        $x_1_20 = "ns2.random.dns.d0wn.biz" ascii //weight: 1
        $x_1_21 = "onyx.deepdns.cryptostorm.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

