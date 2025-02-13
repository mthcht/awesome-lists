rule Virus_WinNT_Necurs_A_2147683528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:WinNT/Necurs.gen!A.dummy"
        threat_id = "2147683528"
        type = "Virus"
        platform = "WinNT: WinNT"
        family = "Necurs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dummy: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Necurs dummy detection" ascii //weight: 1
        $x_1_2 = "Internal test only. Do not distribute outside your team!" ascii //weight: 1
        $x_1_3 = "hAgCAACJBmaBfgSz1w+FwwAAAGTgRqAP826IPm" ascii //weight: 1
        $x_1_4 = "G$MfZMSrNkHKAMKe-+TGF23pEV26cqPT4Xa" ascii //weight: 1
        $x_1_5 = "qXcCfDr2(2XfiMrmal$D--(KqHQB@$UIq`&[dJ#9" ascii //weight: 1
        $x_1_6 = "Je@fp(Kqll[$Vk@IPXaNHe#k2#HVkYKZ" ascii //weight: 1
        $x_1_7 = "SIPFe)I9!6k%,B'5lr%a1H[qjm(*K" ascii //weight: 1
        $x_1_8 = "d&XkfH3l6JrPVj[$YZ*Bq(pPcPR-blQZb" ascii //weight: 1
        $x_1_9 = "HVNOA&@R1!cP!C6S-84dIKk+&i3q4JKqDd)#4UAG4" ascii //weight: 1
        $x_1_10 = "-MZELCr00k&2NJ*jk8!,@B'H@`km#Z1`+ki#[U-#Y" ascii //weight: 1
        $x_1_11 = "9MHrK6mZEbUBD&X@e*zP&[A4QMa@C@&p" ascii //weight: 1
        $x_1_12 = "ImYqjRrRmRirm[mI3rZa2cIjIeBRjIbH$I1aIcIiiZ" ascii //weight: 1
        $x_1_13 = "MjNsRcpT0ND$fcabG!8(M))5GpDIGKPVZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

