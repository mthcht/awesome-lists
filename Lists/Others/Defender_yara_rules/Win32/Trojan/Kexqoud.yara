rule Trojan_Win32_Kexqoud_A_2147681343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kexqoud.gen!A"
        threat_id = "2147681343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kexqoud"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {73 69 6f 6e 5c 52 75 6e 00 41 50 50 44 41 54 41 00 25 73 5c 25 73 2e 65 78 65 00 23 38 30 30 31}  //weight: 20, accuracy: High
        $x_20_2 = {50 00 8b 45 f8 8b 55 fc 2d 00 80 3e d5 81 da de b1 9d 01 52 50 6a 00 68 80 96 98 00 e8}  //weight: 20, accuracy: High
        $x_1_3 = "botscoolnesss_cpu:123@us2.eclipsemc.com:8337" ascii //weight: 1
        $x_1_4 = "1ES11Ke5mxgz9MYiJ2Pb1MgY2FFYnfs5fA:x@mining.eligius.st:8337" ascii //weight: 1
        $x_1_5 = "hitmanuk_cheap:123@port80.btcguild.com:80" ascii //weight: 1
        $x_1_6 = "blackweader@hotmail.com_roby:burtshaga-q1w2e3r4@pool.50btc.com:8332" ascii //weight: 1
        $x_1_7 = "-g yes -o http://hitmanuk.bit:bit@api.bitcoin.cz:8332" ascii //weight: 1
        $x_1_8 = "system.exe -o http://hitmanuk_multi:123@btcguild.com:8332" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

