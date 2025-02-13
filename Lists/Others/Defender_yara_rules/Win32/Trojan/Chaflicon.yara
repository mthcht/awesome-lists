rule Trojan_Win32_Chaflicon_A_2147687736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chaflicon.A"
        threat_id = "2147687736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chaflicon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "4CEE25DB0B37231C0129D808" ascii //weight: 2
        $x_2_2 = "56D80FCD79A5AE51F41AC17684BC5F83A45F9F53C0" ascii //weight: 2
        $x_2_3 = "AF4AC957DF7E8A95919490AE4DD06F9C" ascii //weight: 2
        $x_2_4 = "1B37C154E664EE778EAEA2ABB448EA" ascii //weight: 2
        $x_2_5 = "9CB649CB59E46FF70F121E2F3AC36E" ascii //weight: 2
        $x_2_6 = "6985959BAEB1BD44D962EE7E839AB8" ascii //weight: 2
        $x_1_7 = "021C2C3039CC5BFA0B24" ascii //weight: 1
        $x_1_8 = "DC79FB15223DCB57E660FF10" ascii //weight: 1
        $x_1_9 = "35D15CF50119213AC56F" ascii //weight: 1
        $x_1_10 = "D772FC142330CA59E072" ascii //weight: 1
        $x_1_11 = "718D97AEB942CA57E173" ascii //weight: 1
        $x_1_12 = "EA0709182F3DC55BD456E50E" ascii //weight: 1
        $x_1_13 = "16303ACC5DEA799896BF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Chaflicon_B_2147687907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chaflicon.B"
        threat_id = "2147687907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chaflicon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "B94FA8C62C3539D45CF1" ascii //weight: 1
        $x_1_2 = "F40A6380E97F879CB4B14DE1" ascii //weight: 1
        $x_1_3 = "7D82FB678E9CA8BF52E7" ascii //weight: 1
        $x_1_4 = "6798ED75FC10202034D9" ascii //weight: 1
        $x_1_5 = "F90F668DE477FB0A1B30" ascii //weight: 1
        $x_1_6 = "BB4DA0C32D31C355DF6DF61F" ascii //weight: 1
        $x_1_7 = "7788E50276F97C9190A5" ascii //weight: 1
        $x_2_8 = "61E61956AE47CF67EA7A8A96A7B656E2" ascii //weight: 2
        $x_2_9 = "7394D32A41CE51E5728E86819DA0AD" ascii //weight: 2
        $x_2_10 = "758AEB0C60E768F207131D2A34C977" ascii //weight: 2
        $x_2_11 = "AD539AE802171B2F3DC44FD853EA18" ascii //weight: 2
        $x_2_12 = "8AAF26AF27CE78EE67DD0B3CE5" ascii //weight: 2
        $x_2_13 = "9481D57DF92BDB0938E4033EC16C89BF53" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Chaflicon_C_2147688159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chaflicon.C"
        threat_id = "2147688159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chaflicon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 17 89 d0 33 d2 89 17 8b e8 ff d5 83 3f 00 75 ?? 83 3d ?? ?? ?? ?? 00 74 11 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "[VERSAOLOADER]" ascii //weight: 1
        $x_1_3 = "[LINKCONTADO" ascii //weight: 1
        $x_1_4 = "[FTPUSER]" ascii //weight: 1
        $x_1_5 = "[LINKEXE]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

