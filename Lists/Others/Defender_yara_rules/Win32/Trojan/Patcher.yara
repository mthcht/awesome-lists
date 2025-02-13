rule Trojan_Win32_Patcher_B_2147609499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Patcher.B"
        threat_id = "2147609499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Patcher"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "160"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {03 08 51 50 8b 40 04 91 c1 e9 02 81 30 2f 88 b8 00 c1 00 02 83 c0 04 e2 f2 58 59 8b 40 04 53 54 50 51 ff 35 bc 81 40 00 e8 95 58 00 00}  //weight: 100, accuracy: High
        $x_20_2 = "e-Safekey" wide //weight: 20
        $x_20_3 = "EBJSecurity_3" wide //weight: 20
        $x_20_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\rbt" ascii //weight: 20
        $x_1_5 = "Jo1ezdsl" ascii //weight: 1
        $x_1_6 = "powrprof.dll" ascii //weight: 1
        $x_1_7 = "conlf.ini" ascii //weight: 1
        $x_1_8 = "kerdnp.ini" ascii //weight: 1
        $x_1_9 = "korlg.ini" ascii //weight: 1
        $x_1_10 = "nwklr.ini" ascii //weight: 1
        $x_1_11 = "nwpp.ini" ascii //weight: 1
        $x_1_12 = "nwwlnt.ini" ascii //weight: 1
        $x_1_13 = "ppdnp.ini" ascii //weight: 1
        $x_1_14 = "pporlg.ini" ascii //weight: 1
        $x_1_15 = "windmlp.ini" ascii //weight: 1
        $x_1_16 = "worlg.ini" ascii //weight: 1
        $x_1_17 = "ldshyr.old" ascii //weight: 1
        $x_40_18 = {e8 00 00 00 00 58 05 ?? ?? ?? ?? ff e0 60 e8 00 00 00}  //weight: 40, accuracy: Low
        $x_100_19 = {41 ad 33 db 90 0f be 54 05 00 38 f2 74 08 c1 cb 0d 03 da 40 eb ef 3b df 75 e6 5e}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_40_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

